package webserver

/**
Handling of webserver and requests / uploads
*/

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	templatetext "text/template"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/environment"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/logging/serverstats"
	"github.com/forceu/gokapi/internal/mail"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/storage"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/storage/filerequest"
	"github.com/forceu/gokapi/internal/storage/presign"
	"github.com/forceu/gokapi/internal/webserver/api"
	"github.com/forceu/gokapi/internal/webserver/authentication"
	"github.com/forceu/gokapi/internal/webserver/authentication/csrftoken"
	"github.com/forceu/gokapi/internal/webserver/authentication/downloadPasswordToken"
	"github.com/forceu/gokapi/internal/webserver/authentication/oauth"
	"github.com/forceu/gokapi/internal/webserver/authentication/sessionmanager"
	"github.com/forceu/gokapi/internal/webserver/authentication/tokengeneration"
	"github.com/forceu/gokapi/internal/webserver/errorHandling"
	"github.com/forceu/gokapi/internal/webserver/favicon"
	"github.com/forceu/gokapi/internal/webserver/fileupload"
	"github.com/forceu/gokapi/internal/webserver/ratelimiter"
	"github.com/forceu/gokapi/internal/webserver/sse"
	"github.com/forceu/gokapi/internal/webserver/ssl"
)

// TODO add 404 handler

// staticFolderEmbedded is the embedded version of the "static" folder
// This contains JS files, CSS, images etc
//
//go:embed web/static
var staticFolderEmbedded embed.FS

// templateFolderEmbedded is the embedded version of the "templates" folder
// This contains templates that Gokapi uses for creating the HTML output
//
//go:embed web/templates
var templateFolderEmbedded embed.FS

// wasmDownloadFile is the compiled binary of the wasm downloader
// Will be generated with go generate ./...
//
//go:embed web/main.wasm
var wasmDownloadFile embed.FS

// wasmE2EFile is the compiled binary of the wasm e2e encrypter
// Will be generated with go generate ./...
//
//go:embed web/e2e.wasm
var wasmE2EFile embed.FS

const timeOutWebserverRead = 2 * time.Hour
const timeOutWebserverWrite = 12 * time.Hour

// templateFolder contains all parsed templates
var templateFolder *template.Template

// customStaticInfo is passed to all templates, so custom CSS or JS can be embedded
var customStaticInfo customStatic

// imageExpiredPicture is sent for an expired hotlink
var imageExpiredPicture []byte

// srv is the web server that is used for this module
var srv http.Server

// Start the webserver on the port set in the config
func Start() {
	initTemplates(templateFolderEmbedded)
	webserverDir, _ := fs.Sub(staticFolderEmbedded, "web/static")
	var err error

	loadCustomCssJsInfo(webserverDir)
	loadExpiryImage()

	mux := createMux(webserverDir, configuration.GetEnvironment().DisableBuiltinUI)

	fmt.Println("Binding webserver to " + configuration.Get().Port)
	srv = http.Server{
		Addr:         configuration.Get().Port,
		ReadTimeout:  timeOutWebserverRead,
		WriteTimeout: timeOutWebserverWrite,
		Handler:      mux,
	}
	infoMessage := "Webserver can be accessed at " + configuration.Get().ServerUrl + "admin\nPress CTRL+C to stop Gokapi"
	if strings.Contains(configuration.Get().ServerUrl, "127.0.0.1") {
		if configuration.Get().UseSsl {
			infoMessage = strings.Replace(infoMessage, "http://", "https://", 1)
		} else {
			infoMessage = strings.Replace(infoMessage, "https://", "http://", 1)
		}
	}
	if configuration.Get().UseSsl {
		ssl.GenerateIfInvalidCert(configuration.Get().ServerUrl, false)
		fmt.Println(infoMessage)
		err = srv.ListenAndServeTLS(ssl.GetCertificateLocations())
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	} else {
		fmt.Println(infoMessage)
		err = srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}

// createMux registers all routes. The routes are split into two groups, because the stock
// Gokapi interface has been replaced by a standalone SPA served from a reverse proxy: with
// disableBuiltinUI set, only the endpoints that SPA (and the API) actually call are exposed.
// The stock pages are not merely dead weight then, they are an attack surface: /d, /h/ and
// the other anonymous download templates hand out file bytes without going through the
// identity-restricted share checks the SPA flow relies on, so they must be absent, not
// just unlinked.
func createMux(webserverDir fs.FS, disableBuiltinUI bool) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth/token", requireLogin(handleGenerateAuthToken, false, false))
	mux.HandleFunc("/api/", processApi)
	mux.HandleFunc("/downloadFile", downloadFile)
	mux.HandleFunc("/downloadPresigned", requireLogin(downloadPresigned, false, false))
	// The error page stays available in both modes: the download endpoints above redirect
	// to it for invalid or denied requests, and without it those redirects would dead-end
	// in a 404 that looks like a broken server rather than a denied request. With the
	// built-in UI off it renders without the stock CSS (served from "/"), which is
	// acceptable for a page whose only job is to state that a link did not work.
	mux.HandleFunc("/error", showError)
	mux.HandleFunc("/login", showLogin)
	mux.HandleFunc("/logout", doLogout)
	mux.HandleFunc("/pubapi/config", pubApiConfig)
	mux.HandleFunc("/pubapi/error", pubApiError)
	mux.HandleFunc("/pubapi/file", pubApiFileMetadata)
	mux.HandleFunc("/pubapi/filepassword", pubApiFilePassword)
	mux.HandleFunc("/pubapi/folder", pubApiFolder)
	mux.HandleFunc("/pubapi/folderpassword", pubApiFolderPassword)
	mux.HandleFunc("/pubapi/folderzip", pubApiFolderZip)
	mux.HandleFunc("/pubapi/uploadrequest", pubApiUploadRequest)
	mux.HandleFunc("/pubapi/share/resend", pubApiShareResend)
	mux.HandleFunc("/uploadChunk", requireLogin(uploadChunk, false, false))
	mux.HandleFunc("/uploadStatus", requireLogin(sse.GetStatusSSE, false, false))
	mux.Handle("/main.wasm", gziphandler.GzipHandler(http.HandlerFunc(serveDownloadWasm)))
	mux.Handle("/e2e.wasm", gziphandler.GzipHandler(http.HandlerFunc(serveE2EWasm)))

	if disableBuiltinUI {
		// With the stock UI off, "/" still answers, but only as a liveness endpoint:
		// the container HEALTHCHECK probes it, and an unregistered "/" would report a
		// healthy server as unhealthy. It deliberately does NOT serve the stock static
		// assets. ServeMux routes every unclaimed path to the "/" pattern, so anything
		// other than exactly "/" must still 404 here -- otherwise the stock routes
		// removed below (/admin, /d, /h/, ...) would start answering 200 again, which
		// is the attack surface this mode exists to remove.
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})
	}

	if !disableBuiltinUI {
		// "/" is the stock static asset server, and in SPA deployments the reverse
		// proxy owns "/", so it is only registered here in built-in-UI mode.
		mux.Handle("/", filesystemHandler(webserverDir))
		mux.HandleFunc("/admin", requireLogin(showAdminMenu, true, false))
		mux.HandleFunc("/apiKeys", requireLogin(showApiAdmin, true, false))
		mux.HandleFunc("/changePassword", requireLogin(changePassword, true, true))
		mux.HandleFunc("/d", showDownload)
		mux.HandleFunc("/e2eSetup", requireLogin(showE2ESetup, true, false))
		mux.HandleFunc("/filerequests", requireLogin(showUploadRequest, true, false))
		mux.HandleFunc("/forgotpw", forgotPassword)
		mux.HandleFunc("/h/", showHotlink)
		mux.HandleFunc("/hotlink/", showHotlink) // backward compatibility
		mux.HandleFunc("/index", showIndex)
		mux.HandleFunc("/logs", requireLogin(showLogs, true, false))
		mux.HandleFunc("/publicUpload", showPublicUpload)
		mux.HandleFunc("/users", requireLogin(showUserAdmin, true, false))
		mux.HandleFunc("/d/{id}/{filename}", redirectFromFilename)
		mux.HandleFunc("/dh/{id}/{filename}", downloadFileWithNameInUrl)
	}

	addMuxForCustomContent(mux)

	authConfig := configuration.Get().Authentication
	isHybrid := authConfig.Method == models.AuthenticationInternal && authConfig.OAuthEnabledAlongsideInternal
	if authConfig.Method == models.AuthenticationOAuth2 || isHybrid {
		oauth.Init(configuration.Get().ServerUrl, authConfig, isHybrid)
		if oauth.IsAvailable() {
			mux.HandleFunc("/oauth-login", oauth.HandlerLogin)
			mux.HandleFunc("/oauth-callback", oauth.HandlerCallback)
		}
	}
	return mux
}

func filesystemHandler(webserverDir fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/favicon") {
			handleFavicon(w, r)
			return
		}
		addCacheHeader(w)
		http.FileServer(http.FS(webserverDir)).ServeHTTP(w, r)
	}
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	icon := favicon.GetFavicon(r.URL.Path)
	_, _ = w.Write(icon)
}

func loadExpiryImage() {
	svgTemplate, err := templatetext.ParseFS(templateFolderEmbedded, "web/templates/expired_file_svg.tmpl")
	helper.Check(err)
	var buf bytes.Buffer
	err = svgTemplate.Execute(&buf, struct {
		PublicName string
	}{PublicName: configuration.Get().PublicName})
	helper.Check(err)
	imageExpiredPicture = buf.Bytes()
}

// Shutdown closes the webserver gracefully
func Shutdown() {
	sse.Shutdown()
	err := srv.Shutdown(context.Background())
	if err != nil {
		log.Println(err)
	}
}

// Initialises the templateFolder variable by scanning through all the templates.
// If a folder "templates" exists in the main directory, it is used.
// Otherwise, templateFolderEmbedded will be used.
func initTemplates(templateFolderEmbedded embed.FS) {
	var err error

	funcMap := template.FuncMap{
		"newAdminButtonContext": newAdminButtonContext,
	}
	if helper.FolderExists("templates") {
		fmt.Println("Found folder 'templates', using local folder instead of internal template folder")
		templateFolder, err = template.New("").Funcs(funcMap).ParseGlob("templates/*.tmpl")
		helper.Check(err)
	} else {
		templateFolder, err = template.New("").Funcs(funcMap).ParseFS(templateFolderEmbedded, "web/templates/*.tmpl")
		helper.Check(err)
	}
}

// Sends a redirect HTTP output to the client. Variable url is used to redirect to ./url
func redirect(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func redirectOnIncorrectId(w http.ResponseWriter, r *http.Request, url string) {
	ratelimiter.WaitOnFailedId(r)
	redirect(w, r, url)
}

type redirectValues struct {
	FileId           string
	RedirectUrl      string
	Name             string
	Size             string
	PublicName       string
	BaseUrl          string
	PasswordRequired bool
}

// Handling of /id/?/? - used when filename shall be displayed, will redirect to the regular download URL
func redirectFromFilename(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	id := r.PathValue("id")
	file, ok := storage.GetFile(id)
	if !ok {
		// Covers an unknown id, an expired file and a file pending deletion alike: GetFile does
		// not distinguish the reason. Unknown-id probes are an enumeration signal worth
		// recording on their own (PLAN.md), not just outright denials against a real file.
		if err := logging.LogDownloadDenied(models.File{Id: id}, r, configuration.Get().SaveIp, "unknown, expired, or invalid file id"); err != nil {
			respondAuditWriteFailed(w)
			return
		}
		redirect(w, r, "../../error")
		return
	}

	config := configuration.Get()
	err := templateFolder.ExecuteTemplate(w, "redirect_filename", redirectValues{
		FileId:           id,
		RedirectUrl:      "d",
		Name:             file.Name,
		Size:             file.Size,
		PublicName:       config.PublicName,
		BaseUrl:          config.ServerUrl,
		PasswordRequired: file.PasswordHash != ""})
	helper.CheckIgnoreTimeout(err)
}

// Handling of /main.wasm
func serveDownloadWasm(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "public, max-age=100800") // 2 days
	w.Header().Set("Content-Type", "application/wasm")
	file, err := wasmDownloadFile.ReadFile("web/main.wasm")
	helper.Check(err)
	_, _ = w.Write(file)
}

// Handling of /e2e.wasm
func serveE2EWasm(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "public, max-age=100800") // 2 days
	w.Header().Set("Content-Type", "application/wasm")
	file, err := wasmE2EFile.ReadFile("web/e2e.wasm")
	helper.Check(err)
	_, _ = w.Write(file)
}

// Handling of /logout
func doLogout(w http.ResponseWriter, r *http.Request) {
	user, isLoggedIn, err := authentication.IsAuthenticated(w, r)
	authentication.Logout(w, r)
	if err == nil && isLoggedIn {
		logging.LogLogout(user, r)
	}
}

// Handling of /index and redirecting to globalConfig.RedirectUrl
func showIndex(w http.ResponseWriter, r *http.Request) {
	err := templateFolder.ExecuteTemplate(w, "index", genericView{RedirectUrl: configuration.Get().RedirectUrl,
		PublicName:    configuration.Get().PublicName,
		CustomContent: customStaticInfo})
	helper.CheckIgnoreTimeout(err)
}

func handleGenerateAuthToken(w http.ResponseWriter, r *http.Request) {
	user, err := authentication.GetUserFromRequest(r)
	if err != nil {
		panic(err)
	}
	permString := r.Header.Get("permission")
	permission, err := models.ApiPermissionFromString(permString)
	if err != nil {
		http.Error(w, "Invalid permission", http.StatusBadRequest)
		return
	}
	token, expiry, err := tokengeneration.Generate(user, permission)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_, _ = w.Write([]byte("{\"key\":\"" + token + "\",\"expiry\":" + strconv.FormatInt(expiry, 10) + "}"))
}

// Handling of /changePassword
func changePassword(w http.ResponseWriter, r *http.Request) {
	var errMessage string
	user, err := authentication.GetUserFromRequest(r)
	if err != nil {
		panic(err)
	}
	// A user not provisioned for internal auth must never be able to set a password through
	// this form, even if ResetPassword were somehow true for such a row: a password here would
	// reopen the internal login door that IsCorrectUsernameAndPassword closes for them.
	if !user.ResetPassword || user.AuthProvider != models.AuthProviderInternal {
		redirect(w, r, "admin")
		return
	}
	err = r.ParseForm()
	if err != nil {
		fmt.Println("Invalid form data sent to server for /changePassword")
		fmt.Println(err)
		errMessage = "Invalid form data sent"
	} else {
		var ok bool
		var pwHash string

		pw := r.PostForm.Get("newpw")
		csrf := r.PostForm.Get("csrf-token")
		pwHash, ok, err = validateNewPassword(pw, user, csrf)
		if err != nil {
			errMessage = firstLetterUpper(err.Error())
		}
		if ok {
			user.Password = pwHash
			user.ResetPassword = false
			database.SaveUser(user, false)
			redirect(w, r, "admin")
			return
		}
	}
	config := configuration.Get()
	err = templateFolder.ExecuteTemplate(w, "changepw",
		genericView{PublicName: config.PublicName,
			MinPasswordLength: configuration.GetEnvironment().MinLengthPassword,
			ErrorMessage:      errMessage,
			CustomContent:     customStaticInfo,
			CsrfToken:         csrftoken.Generate(csrftoken.TypeLogin)})
	helper.CheckIgnoreTimeout(err)
}

// validateNewPassword validates the new password and returns the new password hash if the password is valid.
// If the password is not valid, it returns an error message and an empty string.
// If the password is valid, it returns the hash as a string and true.
func validateNewPassword(newPassword string, user models.User, userCsrfToken string) (string, bool, error) {
	if len(newPassword) == 0 {
		return user.Password, false, nil
	}
	if !csrftoken.IsValid(csrftoken.TypeLogin, userCsrfToken) {
		return "", false, errors.New("form was not submitted completely")
	}
	if len(newPassword) < configuration.GetEnvironment().MinLengthPassword {
		return "", false, errors.New("password is too short")
	}
	err := configuration.ValidatePasswordComplexity(newPassword)
	if err != nil {
		return "", false, err
	}
	isSame, _ := configuration.VerifyPassword(newPassword, user.Password, "")
	if isSame {
		return "", false, errors.New("new password has to be different from the old password")
	}
	newPasswordHash := configuration.HashPassword(newPassword, false, "")
	return newPasswordHash, true, nil
}

func firstLetterUpper(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(string(s[0])) + s[1:]
}

// Handling of /error
func showError(w http.ResponseWriter, r *http.Request) {

	displayedError := errorHandling.Get(r)

	if r.URL.Query().Has("e2e") {
		displayedError.ErrorId = errorHandling.TypeE2ECipher
		displayedError.IsGeneric = true
		displayedError.CardWidth = "25rem"
	}

	err := templateFolder.ExecuteTemplate(w, "error", genericView{
		ErrorId:           displayedError.ErrorId,
		ErrorCardWidth:    displayedError.CardWidth,
		IsGenericError:    displayedError.IsGeneric,
		ErrorTitle:        displayedError.Title,
		ErrorMessage:      displayedError.Message,
		ErrorOauthMessage: displayedError.OAuthProviderMessage,
		PublicName:        configuration.Get().PublicName,
		CustomContent:     customStaticInfo})
	helper.CheckIgnoreTimeout(err)
}

// Handling of /forgotpw
func forgotPassword(w http.ResponseWriter, r *http.Request) {
	err := templateFolder.ExecuteTemplate(w, "forgotpw", genericView{
		PublicName:    configuration.Get().PublicName,
		CustomContent: customStaticInfo})
	helper.CheckIgnoreTimeout(err)
}

// Handling of /filerequest
func showUploadRequest(w http.ResponseWriter, r *http.Request) {
	userId, err := authentication.GetUserFromRequest(r)
	if err != nil {
		panic(err)
	}
	view := (&AdminView{}).convertGlobalConfig(ViewFileRequests, userId)

	if !view.ActiveUser.HasPermissionCreateFileRequests() {
		redirect(w, r, "admin")
		return
	}
	err = templateFolder.ExecuteTemplate(w, "uploadreq", view)
	helper.CheckIgnoreTimeout(err)
}

// Handling of /api
// If the user is authenticated, this menu lists all uploads and enables uploading new files
func showApiAdmin(w http.ResponseWriter, r *http.Request) {
	userId, err := authentication.GetUserFromRequest(r)
	if err != nil {
		panic(err)
	}
	view := (&AdminView{}).convertGlobalConfig(ViewAPI, userId)

	if configuration.GetEnvironment().DisableApiMenu && !view.ActiveUser.IsAdmin() {
		redirect(w, r, "admin")
		return
	}

	err = templateFolder.ExecuteTemplate(w, "api", view)
	helper.CheckIgnoreTimeout(err)
}

// Handling of /users
// If user is authenticated, this menu lists all users
func showUserAdmin(w http.ResponseWriter, r *http.Request) {
	userId, err := authentication.GetUserFromRequest(r)
	if err != nil {
		panic(err)
	}
	view := (&AdminView{}).convertGlobalConfig(ViewUsers, userId)
	if !view.ActiveUser.HasPermissionManageUsers() || configuration.Get().Authentication.Method == models.AuthenticationDisabled {
		redirect(w, r, "admin")
		return
	}
	err = templateFolder.ExecuteTemplate(w, "users", view)
	helper.CheckIgnoreTimeout(err)
}

// Handling of /api/
func processApi(w http.ResponseWriter, r *http.Request) {
	api.Process(w, r)
}

// Handling of /login
// Shows a login form. If not authenticated, client needs to wait for three seconds.
// If correct, a new session is created and the user is redirected to the admin menu
func showLogin(w http.ResponseWriter, r *http.Request) {
	_, ok, err := authentication.IsAuthenticated(w, r)
	if err != nil {
		errorHandling.RedirectToErrorPage(w, r, "Unable to log in", "The following error was raised: "+err.Error(), errorHandling.WidthDefault)
		return
	}
	if ok {
		redirect(w, r, "admin")
		return
	}
	if configuration.Get().Authentication.Method == models.AuthenticationHeader {
		errorHandling.RedirectToErrorPage(w, r, "Unauthorised",
			"No login information was sent from the authentication provider.", errorHandling.WidthDefault)
		return
	}
	authConfig := configuration.Get().Authentication
	isHybrid := authConfig.Method == models.AuthenticationInternal && authConfig.OAuthEnabledAlongsideInternal
	if authConfig.Method == models.AuthenticationOAuth2 && !isHybrid {
		// If user clicked logout, force consent
		if r.URL.Query().Has("consent") {
			redirect(w, r, "oauth-login?consent=true")
		} else {
			redirect(w, r, "oauth-login")
		}
		return
	}
	if isHybrid && r.URL.Query().Has("consent") {
		// Hybrid mode shows the login choice page here rather than redirecting straight to
		// oauth-login, so the consent hint on the URL cannot simply be forwarded through a
		// redirect like the OAuth2-only case above. Set a short-lived cookie instead: this makes
		// the next OAuth login request consent, independently of whether the client that renders
		// this page (e.g. the SPA) also happens to forward the query string itself.
		oauth.SetForceConsentHint(w)
	}
	err = r.ParseForm()
	if err != nil {
		fmt.Println("Invalid form data sent to server for /login")
		fmt.Println(err)
		return
	}
	user := r.PostForm.Get("username")
	pw := r.PostForm.Get("password")
	csfr := r.PostForm.Get("csrf-token")
	failedLogin := false
	failedCsrf := false
	if pw != "" && user != "" {
		ip := logging.GetIpAddress(r)
		ratelimiter.WaitOnLogin(ip)
		retrievedUser, validCredentials, validCsfr := authentication.IsCorrectUsernameAndPassword(user, pw, csfr)
		if validCredentials {
			logging.LogValidLogin(user, "", ip)
			sessionmanager.CreateSession(w, false, 0, retrievedUser.Id)
			redirect(w, r, "admin")
			return
		}
		if validCsfr {
			logging.LogInvalidLogin(user, ip)
		}
		failedCsrf = !validCsfr
		failedLogin = true
	}
	err = templateFolder.ExecuteTemplate(w, "login", LoginView{
		IsFailedLogin: failedLogin,
		IsFailedCsfr:  failedCsrf,
		User:          user,
		IsAdminView:   false,
		PublicName:    configuration.Get().PublicName,
		CustomContent: customStaticInfo,
		CsrfToken:     csrftoken.Generate(csrftoken.TypeLogin),
	})
	helper.CheckIgnoreTimeout(err)
}

// LoginView contains variables for the login template
type LoginView struct {
	IsFailedLogin  bool
	IsFailedCsfr   bool
	IsAdminView    bool
	IsDownloadView bool
	User           string
	PublicName     string
	CsrfToken      string
	CustomContent  customStatic
}

// Handling of /d
// Checks if a file exists for the submitted ID
// If it exists, a download form is shown, or a password needs to be entered.
func showDownload(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	keyId := queryUrl(w, r, "id", errorHandling.TypeFileNotFound)
	file, ok := storage.GetFile(keyId)
	if !ok || file.IsFileRequest() {
		// Covers an unknown id, an expired file and a file pending deletion alike: GetFile does
		// not distinguish the reason. Unknown-id probes are an enumeration signal worth
		// recording on their own (PLAN.md), not just outright denials against a real file.
		if err := logging.LogDownloadDenied(models.File{Id: keyId}, r, configuration.Get().SaveIp, "unknown, expired, or invalid file id"); err != nil {
			respondAuditWriteFailed(w)
			return
		}
		redirectOnIncorrectId(w, r, "error")
		return
	}

	config := configuration.Get()

	view := DownloadView{
		Name:               file.Name,
		Size:               file.Size,
		Id:                 file.Id,
		IsDownloadView:     true,
		EndToEndEncryption: file.Encryption.IsEndToEndEncrypted,
		PublicName:         config.PublicName,
		BaseUrl:            config.ServerUrl,
		IsFailedLogin:      false,
		UsesHttps:          configuration.UsesHttps(),
		PrivacyNotice:      privacyNoticeText,
		CustomContent:      customStaticInfo,
	}

	if file.RequiresClientDecryption() {
		view.ClientSideDecryption = true
		if !file.Encryption.IsEndToEndEncrypted {
			// Only reachable for a server-side encrypted file that is not stored locally (e.g.
			// FullEncryptionInput with S3/AWS storage - see models.File.RequiresClientDecryption).
			// The page needs the file's cipher to hand the client so it can decrypt after
			// download, which needs the master key; while sealed that key does not exist yet, so
			// refuse cleanly here instead of letting GetCipherFromFile's error reach helper.Check
			// (which would panic the request).
			if encryption.IsSealed() {
				errorHandling.RedirectToErrorPage(w, r, "Instance sealed",
					"This server instance is sealed and cannot serve this file until an administrator unseals it.", errorHandling.WidthDefault)
				return
			}
			cipher, err := encryption.GetCipherFromFile(file.Encryption)
			helper.Check(err)
			view.Cipher = base64.StdEncoding.EncodeToString(cipher)
		}
	}

	if file.PasswordHash != "" && !isValidPwCookie(r, file) {
		_ = r.ParseForm()
		enteredPassword := r.PostForm.Get("password")
		if enteredPassword == "" {
			view.IsPasswordView = true
			err := templateFolder.ExecuteTemplate(w, "download_password", view)
			helper.CheckIgnoreTimeout(err)
			return
		}

		ip := logging.GetIpAddress(r)
		ratelimiter.WaitOnDownloadPassword(ip)

		// Trim to match ValidateSharePassword, which trims before hashing whatever value
		// was used to protect the share - see the identical comment in pubApiFilePassword.
		// The emptiness check above stays on the untrimmed value, so a whitespace-only
		// submission still re-shows the password prompt rather than being treated as a
		// (trimmed-away) password guess.
		trimmedPassword := strings.TrimSpace(enteredPassword)
		isValid, isLegacy := configuration.VerifyPassword(trimmedPassword, file.PasswordHash, configuration.Get().Authentication.SaltFiles)
		if isValid {
			// Migrate legacy passwords to the new format
			// Will be removed in the future
			if isLegacy {
				file.PasswordHash = configuration.HashPassword(trimmedPassword, false, "")
				database.SaveMetaData(file)
			}
			writeFilePwCookie(w, file)
			// redirect so that there is no post data to be resent if user refreshes page
			redirect(w, r, "d?id="+file.Id)
			return
		}
		if err := logging.LogDownloadDenied(file, r, config.SaveIp, "incorrect password"); err != nil {
			respondAuditWriteFailed(w)
			return
		}
		view.IsFailedLogin = true
		view.IsPasswordView = true
		err := templateFolder.ExecuteTemplate(w, "download_password", view)
		helper.CheckIgnoreTimeout(err)
		return
	}

	err := templateFolder.ExecuteTemplate(w, "download", view)
	helper.CheckIgnoreTimeout(err)
}

// Handling of /h/ and /hotlink/
// Hotlinks an image or returns a static error image if image has expired
func showHotlink(w http.ResponseWriter, r *http.Request) {
	hotlinkId := strings.Replace(r.URL.Path, "/hotlink/", "", 1)
	hotlinkId = strings.Replace(hotlinkId, "/h/", "", 1)
	addNoCacheHeader(w)
	file, ok := storage.GetFileByHotlink(hotlinkId)
	if !ok || file.IsFileRequest() {
		// Covers an unknown hotlink id, an expired file and a file pending deletion alike:
		// GetFileByHotlink does not distinguish the reason. Unknown-id probes are an
		// enumeration signal worth recording on their own (PLAN.md).
		if err := logging.LogDownloadDenied(models.File{Id: hotlinkId}, r, configuration.Get().SaveIp, "unknown, expired, or invalid hotlink id"); err != nil {
			respondAuditWriteFailed(w)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(imageExpiredPicture)
		return
	}
	validFile := storage.ServeFile(file, w, r, false, true, false, true)
	if !validFile {
		// Called if the file has expired or its download allowance was exhausted, checked
		// during storage.ServeFile()
		if err := logging.LogDownloadDenied(file, r, configuration.Get().SaveIp, "link expired or download allowance exhausted"); err != nil {
			respondAuditWriteFailed(w)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(imageExpiredPicture)
		return
	}
}

// Checks if a file is associated with the GET parameter from the current URL
// respondPubApiNotFound rate limits and writes a generic 404 JSON body. Used by every
// /pubapi/* handler when a well-formed id/key does not resolve to an existing entity, so that
// probing for valid ids on these unauthenticated public endpoints is throttled the same way
// ratelimiter.WaitOnFailedId already throttles bad ids on the non-pubapi download door (see
// redirectOnIncorrectId). The id/key-missing-or-too-short case is rate limited separately, inside
// queryUrl itself.
func respondPubApiNotFound(w http.ResponseWriter, r *http.Request) {
	ratelimiter.WaitOnFailedId(r)
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "{\"error\":\"not found\"}")
}

func queryUrl(w http.ResponseWriter, r *http.Request, keyword string, errorType int) string {
	keys, ok := r.URL.Query()[keyword]
	if !ok || len(keys[0]) < environment.MinLengthId {
		// A missing or too-short id/key is the cheapest possible probe against every /pubapi/*
		// endpoint (and the few other callers of queryUrl): no valid-looking id is even needed.
		// Rate limit it here so it is covered everywhere queryUrl is used, rather than requiring
		// every call site to remember to do it individually.
		ratelimiter.WaitOnFailedId(r)
		errorHandling.RedirectGenericErrorPage(w, r, errorType)
		return ""
	}
	return keys[0]
}

// Handling of /admin
// If user is authenticated, this menu lists all uploads and enables uploading new files
func showAdminMenu(w http.ResponseWriter, r *http.Request) {
	user, err := authentication.GetUserFromRequest(r)
	if err != nil {
		panic(err)
	}

	config := configuration.Get()
	if config.Encryption.Level == encryption.EndToEndEncryption {
		e2einfo := database.GetEnd2EndInfo(user.Id)
		if !e2einfo.HasBeenSetUp() {
			redirect(w, r, "e2eSetup")
			return
		}
	}

	view := (&AdminView{}).convertGlobalConfig(ViewMain, user)
	if len(configuration.GetEnvironment().ActiveDeprecations) > 0 {
		if user.IsSuperAdmin() {
			view.ShowDeprecationNotice = true
		}
	}

	err = templateFolder.ExecuteTemplate(w, "admin", view)
	helper.CheckIgnoreTimeout(err)
}

// Handling of /logs
// If user is authenticated, this menu shows the stored logs
func showLogs(w http.ResponseWriter, r *http.Request) {
	user, err := authentication.GetUserFromRequest(r)
	if err != nil {
		panic(err)
	}
	view := (&AdminView{}).convertGlobalConfig(ViewLogs, user)
	if !view.ActiveUser.HasPermissionManageLogs() {
		redirect(w, r, "admin")
		return
	}
	err = templateFolder.ExecuteTemplate(w, "logs", view)
	helper.CheckIgnoreTimeout(err)
}

func showE2ESetup(w http.ResponseWriter, r *http.Request) {
	if configuration.Get().Encryption.Level != encryption.EndToEndEncryption {
		redirect(w, r, "admin")
		return
	}

	user, err := authentication.GetUserFromRequest(r)
	if err != nil {
		panic(err)
	}
	e2einfo := database.GetEnd2EndInfo(user.Id)
	err = templateFolder.ExecuteTemplate(w, "e2esetup", e2ESetupView{
		HasBeenSetup:  e2einfo.HasBeenSetUp(),
		PublicName:    configuration.Get().PublicName,
		CustomContent: customStaticInfo})
	helper.CheckIgnoreTimeout(err)
}

// privacyNoticeText discloses that access details are recorded, as required on the public
// download, download-password and file-request upload pages (PLAN.md W7: the audit log this
// item introduces is a PI repository, and PIPEDA disclosure is part of this item, not
// optional). The final wording, and a defined retention period, belong to a separate item
// (PLAN.md notes "W12 owns the wording"); this is a minimal, honest placeholder so the
// disclosure obligation itself is not silently dropped while that wording is pending - it is
// deliberately renderable as a single template value so W12 only has to replace this constant.
const privacyNoticeText = "For security purposes, this server records the IP address, timestamp and file " +
	"identifier associated with this action. Retention period: not yet defined by this instance's operator."

// DownloadView contains parameters for the download template
type DownloadView struct {
	Name                 string
	Size                 string
	Id                   string
	Cipher               string
	PublicName           string
	BaseUrl              string
	IsFailedLogin        bool
	IsAdminView          bool
	IsDownloadView       bool
	IsPasswordView       bool
	ClientSideDecryption bool
	EndToEndEncryption   bool
	UsesHttps            bool
	PrivacyNotice        string
	CustomContent        customStatic
}

type e2ESetupView struct {
	IsAdminView    bool
	IsDownloadView bool
	HasBeenSetup   bool
	PublicName     string
	CustomContent  customStatic
}

// AdminView contains parameters for all admin-related pages
type AdminView struct {
	Items                 []models.FileApiOutput
	ApiKeys               []models.ApiKey
	Users                 []userInfo
	FileRequests          []models.FileRequest
	ActiveUser            models.User
	UserMap               map[int]*models.User
	ServerUrl             string
	PublicName            string
	IsAdminView           bool
	IsDownloadView        bool
	IsApiView             bool
	IsLogoutAvailable     bool
	IsUserTabAvailable    bool
	EndToEndEncryption    bool
	IncludeFilename       bool
	IsInternalAuth        bool
	ShowApiMenu           bool
	ShowDeprecationNotice bool
	MaxFileSize           int
	ActiveView            int
	ChunkSize             int
	MaxParallelUploads    int
	MinLengthPassword     int
	FileRequestMaxFiles   int
	FileRequestMaxSize    int
	TotalFiles            int
	CpuLoad               int
	MemoryUsagePercent    int
	DiskUsagePercent      int
	DataServed            int64
	Uptime                int64
	TimeNow               int64
	TrafficSince          int64
	MemoryUsage           uint64
	MemoryTotal           uint64
	DiskUsage             uint64
	DiskTotal             uint64
	TotalTraffic          uint64

	CustomContent customStatic
}

// getUserMap needs to return the map with pointers; otherwise template cannot call
// functions associated with it
func getUserMap() map[int]*models.User {
	result := make(map[int]*models.User)
	users := database.GetAllUsers()
	for _, user := range users {
		result[user.Id] = &user
	}
	return result
}

const (
	// ViewMain is the identifier for the main menu
	ViewMain = iota
	// ViewLogs is the identifier for the log viewer menu
	ViewLogs
	// ViewAPI is the identifier for the API menu
	ViewAPI
	// ViewUsers is the identifier for the user management menu
	ViewUsers
	// ViewFileRequests is the identifier for the file request menu
	ViewFileRequests
)

// Converts the globalConfig variable to an AdminView struct to pass the infos to
// the admin template
func (u *AdminView) convertGlobalConfig(view int, user models.User) *AdminView {
	var metaDataList []models.FileApiOutput
	var apiKeyList []models.ApiKey

	config := configuration.Get()
	u.IsInternalAuth = config.Authentication.Method == models.AuthenticationInternal
	u.ActiveUser = user
	u.UserMap = getUserMap()
	u.CustomContent = customStaticInfo
	switch view {
	case ViewMain:
		for _, element := range database.GetAllMetadata() {
			if element.UserId != user.Id && !user.HasPermissionListOtherUploads() {
				continue
			}
			fileInfo, err := element.ToFileApiOutput(config.ServerUrl, config.IncludeFilename)
			helper.Check(err)
			metaDataList = append(metaDataList, fileInfo)
		}
		metaDataList = sortMetaDataApi(metaDataList)
	case ViewAPI:
		for _, apiKey := range database.GetAllApiKeys() {
			// Double-checking if the owner of the API key exists
			// If the user was manually deleted from the database, this could lead to a crash
			// in the API view
			_, ok := u.UserMap[apiKey.UserId]
			if !ok {
				continue
			}
			if !apiKey.IsSystemKey && !apiKey.IsUploadRequestKey() {
				if apiKey.UserId == user.Id || user.HasPermissionManageApi() {
					apiKeyList = append(apiKeyList, apiKey)
				}
			}
		}
		apiKeyList = sortApiKeys(apiKeyList)
	case ViewLogs:
		u.TotalFiles = serverstats.GetTotalFiles()
		u.Uptime = serverstats.GetUptime()
		u.TotalTraffic, u.TrafficSince = serverstats.GetCurrentTraffic()
		_, u.MemoryUsage, u.MemoryTotal, u.MemoryUsagePercent = serverstats.GetMemoryInfo()
		_, u.DiskUsage, u.DiskTotal, u.DiskUsagePercent = serverstats.GetDiskInfo()
		u.CpuLoad = serverstats.GetCpuUsage()
	case ViewUsers:
		uploadCounts := storage.GetUploadCounts()
		u.Users = make([]userInfo, 0)
		for _, userEntry := range database.GetAllUsers() {
			userWithUploads := userInfo{
				UploadCount: uploadCounts[userEntry.Id],
				User:        userEntry,
			}
			// Otherwise the user is not shown as online, if /users is opened as first page
			if userEntry.Id == user.Id {
				userWithUploads.User.LastOnline = time.Now().Unix()
			}
			u.Users = append(u.Users, userWithUploads)
		}
	case ViewFileRequests:
		for _, fileRequest := range filerequest.GetAll() {
			// Double-checking if the owner of the file request exists
			// If the user was manually deleted from the database, this could lead to a crash
			// in the file request view
			_, ok := u.UserMap[fileRequest.UserId]
			if !ok {
				continue
			}
			if fileRequest.UserId != user.Id && !user.HasPermissionListOtherUploads() {
				continue
			}
			fileRequest.Files = sortMetaData(fileRequest.Files)
			u.FileRequests = append(u.FileRequests, fileRequest)
			if !user.IsAdmin() {
				u.FileRequestMaxFiles = configuration.GetEnvironment().MaxFilesGuestUpload
				u.FileRequestMaxSize = configuration.GetEnvironment().MaxSizeGuestUploadMb
			}
		}
	}

	showApiMenu := true
	if configuration.GetEnvironment().DisableApiMenu {
		showApiMenu = user.IsAdmin()
	}

	u.ServerUrl = config.ServerUrl
	u.Items = metaDataList
	u.PublicName = config.PublicName
	u.ApiKeys = apiKeyList
	u.TimeNow = time.Now().Unix()
	u.IsAdminView = true
	u.ActiveView = view
	u.MaxFileSize = config.MaxFileSizeMB
	u.IsLogoutAvailable = authentication.IsLogoutAvailable()
	u.ShowApiMenu = showApiMenu
	u.IsUserTabAvailable = config.Authentication.Method != models.AuthenticationDisabled
	u.EndToEndEncryption = config.Encryption.Level == encryption.EndToEndEncryption
	u.MaxParallelUploads = config.MaxParallelUploads
	u.ChunkSize = config.ChunkSize
	u.IncludeFilename = config.IncludeFilename
	return u
}

// sortMetaDataApi arranges the provided array so that Fies are sorted by the most recent upload first and if that is equal,
// then by most time remaining first. If that is equal, then sort by ID.
func sortMetaDataApi(input []models.FileApiOutput) []models.FileApiOutput {
	sort.Slice(input[:], func(i, j int) bool {
		if input[i].UploadDate != input[j].UploadDate {
			return input[i].UploadDate > input[j].UploadDate
		}
		if input[i].ExpireAt != input[j].ExpireAt {
			return input[i].ExpireAt > input[j].ExpireAt
		}
		return input[i].Id > input[j].Id
	})
	return input
}

// sortMetaData arranges the provided array so that Fies are sorted by the most recent upload first then sort by ID.
// Currently only used for the files of File Requests, all others use sortMetaDataApi
func sortMetaData(input []models.File) []models.File {
	sort.Slice(input[:], func(i, j int) bool {
		if input[i].UploadDate != input[j].UploadDate {
			return input[i].UploadDate > input[j].UploadDate
		}
		return input[i].Id > input[j].Id
	})
	return input
}

// sortApiKeys arranges the provided array so that API keys are sorted by most recent usage first and if that is equal
// then by ID
func sortApiKeys(input []models.ApiKey) []models.ApiKey {
	sort.Slice(input[:], func(i, j int) bool {
		if input[i].LastUsed != input[j].LastUsed {
			return input[i].LastUsed > input[j].LastUsed
		}
		return input[i].Id < input[j].Id
	})
	return input
}

type userInfo struct {
	UploadCount int
	User        models.User
}

// Handling of /publicUpload
func showPublicUpload(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	fileRequestId := queryUrl(w, r, "id", errorHandling.TypeInvalidFileRequest)
	request, ok := filerequest.Get(fileRequestId)
	if !ok {
		errorHandling.RedirectGenericErrorPage(w, r, errorHandling.TypeInvalidFileRequest)
		return
	}
	if !request.IsUnlimitedTime() && request.Expiry < time.Now().Unix() {
		errorHandling.RedirectGenericErrorPage(w, r, errorHandling.TypeInvalidFileRequest)
		return
	}
	if !request.IsUnlimitedFiles() && request.UploadedFiles >= request.MaxFiles {
		errorHandling.RedirectGenericErrorPage(w, r, errorHandling.TypeInvalidFileRequest)
		return
	}
	apiKey := queryUrl(w, r, "key", errorHandling.TypeInvalidFileRequest)
	if subtle.ConstantTimeCompare([]byte(request.ApiKey), []byte(apiKey)) != 1 {
		errorHandling.RedirectGenericErrorPage(w, r, errorHandling.TypeInvalidFileRequest)
		return
	}

	config := configuration.Get()

	view := publicUploadView{
		PublicName:    config.PublicName,
		ChunkSize:     config.ChunkSize,
		MaxServerSize: config.MaxFileSizeMB,
		FileRequest:   &request,
		PrivacyNotice: privacyNoticeText,
		CustomContent: customStaticInfo,
	}

	err := templateFolder.ExecuteTemplate(w, "publicUpload", view)
	helper.CheckIgnoreTimeout(err)
}

// Handling of /uploadChunk
// If the user is authenticated, this parses the uploaded chunk and stores it
func uploadChunk(w http.ResponseWriter, r *http.Request) {
	maxUpload := int64(configuration.Get().MaxFileSizeMB) * 1024 * 1024
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if r.ContentLength > maxUpload {
		responseError(w, storage.ErrorFileTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	_, err := fileupload.ProcessNewChunk(w, r, false, "", maxUpload)
	responseError(w, err)
}

// Outputs an error in json format if err!=nil
func responseError(w http.ResponseWriter, err error) {
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "{\"Result\":\"error\",\"ErrorMessage\":\""+err.Error()+"\"}")
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			log.Println(err)
		}
	}
}

// Handling of /dh/?/?
// Hotlinks a file and has the filename in the URL
func downloadFileWithNameInUrl(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	serveFile(id, false, w, r)
}

// Handling of /downloadFile
// Outputs the file to the user and reduces the download remaining count for the file
func downloadFile(w http.ResponseWriter, r *http.Request) {
	id := queryUrl(w, r, "id", errorHandling.TypeFileNotFound)
	serveFile(id, true, w, r)
}

// Handling of /downloadPresigned
// Outputs the file to the user and reduces the download remaining count for the file, if requested
func downloadPresigned(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	presignKey, ok := r.URL.Query()["key"]
	if !ok {
		responseError(w, storage.ErrorInvalidPresign)
		return
	}
	presignedUrl, ok := presign.Get(presignKey[0])
	if !ok {
		// The presign key itself is a single-use, short-lived bearer token, not a file
		// identifier, so it is not recorded as the file id here - only the fact that an invalid
		// or expired one was presented.
		if err := logging.LogDownloadDenied(models.File{}, r, configuration.Get().SaveIp, "invalid or expired presigned url"); err != nil {
			respondAuditWriteFailed(w)
			return
		}
		responseError(w, storage.ErrorInvalidPresign)
		return
	}
	files := make([]models.File, 0)
	for _, file := range presignedUrl.FileIds {
		storedFile, ok := storage.GetFile(file)
		if !ok {
			if err := logging.LogDownloadDenied(models.File{Id: file}, r, configuration.Get().SaveIp, "unknown, expired, or invalid file id in presigned url"); err != nil {
				respondAuditWriteFailed(w)
				return
			}
			responseError(w, storage.ErrorFileNotFound)
			return
		}
		files = append(files, storedFile)
	}
	presign.Delete(presignedUrl.Id)

	if len(files) == 1 {
		file := files[0]
		forceDecryption := file.Encryption.IsEncrypted && !file.Encryption.IsEndToEndEncrypted
		storage.ServeFile(file, w, r, true, false, forceDecryption, false)
		return
	}
	storage.ServeFilesAsZip(files, presignedUrl.Filename, w, r)
}

func serveFile(id string, isRootUrl bool, w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	savedFile, ok := storage.GetFile(id)

	if !ok || savedFile.IsFileRequest() {
		// Covers an unknown id, an expired file and a file pending deletion alike: GetFile does
		// not distinguish the reason. Unknown-id probes are an enumeration signal worth
		// recording on their own (PLAN.md), not just outright denials against a real file.
		if err := logging.LogDownloadDenied(models.File{Id: id}, r, configuration.Get().SaveIp, "unknown, expired, or invalid file id"); err != nil {
			respondAuditWriteFailed(w)
			return
		}
		if isRootUrl {
			redirectOnIncorrectId(w, r, "error")
		} else {
			redirectOnIncorrectId(w, r, "../../error")
		}
		return
	}
	// A file that is a member of a restricted bundle carries no grant of its own; the
	// bundle's recipient ACL must cascade to it, or holding the member's individual file id
	// would bypass the bundle restriction entirely. This runs regardless of whether the file
	// itself is also independently restricted, and before anything else below, so a
	// non-recipient never learns more than "not found".
	if savedFile.BundleId != "" && database.IsShareRestricted(models.ShareResourceBundle, savedFile.BundleId) {
		if !mayAccessShare(w, r, models.ShareResourceBundle, savedFile.BundleId) {
			if err := logging.LogDownloadDenied(savedFile, r, configuration.Get().SaveIp,
				"no valid recipient access for the file's restricted bundle"); err != nil {
				respondAuditWriteFailed(w)
				return
			}
			if isRootUrl {
				redirectOnIncorrectId(w, r, "error")
			} else {
				redirectOnIncorrectId(w, r, "../../error")
			}
			return
		}
	}
	// An identity-restricted file is refused before the passcode branch below,
	// because a recipient list supersedes a passcode entirely. Refused as
	// "not found" rather than "forbidden": a 403 would confirm that this ID
	// names a real file to anyone probing IDs.
	if database.IsShareRestricted(models.ShareResourceFile, savedFile.Id) {
		recipientId := recipientFor(w, r, models.ShareResourceFile, savedFile.Id)
		if recipientId == 0 {
			if err := logging.LogDownloadDenied(savedFile, r, configuration.Get().SaveIp,
				"no valid recipient access for a restricted file"); err != nil {
				respondAuditWriteFailed(w)
				return
			}
			if isRootUrl {
				redirectOnIncorrectId(w, r, "error")
			} else {
				redirectOnIncorrectId(w, r, "../../error")
			}
			return
		}
		// The allowance is spent per recipient, so one recipient exhausting
		// theirs does not consume anyone else's.
		if shareaccess.ConsumeDownload(models.ShareResourceFile, savedFile.Id, recipientId) != nil {
			if err := logging.LogDownloadDenied(savedFile, r, configuration.Get().SaveIp,
				"recipient download allowance exhausted"); err != nil {
				respondAuditWriteFailed(w)
				return
			}
			if isRootUrl {
				redirectOnIncorrectId(w, r, "error")
			} else {
				redirectOnIncorrectId(w, r, "../../error")
			}
			return
		}
	} else if savedFile.PasswordHash != "" {
		if !(isValidPwCookie(r, savedFile)) {
			if isRootUrl {
				redirect(w, r, "d?id="+savedFile.Id)
			} else {
				redirect(w, r, "../../d?id="+savedFile.Id)
			}
			return
		}
	}
	// The bundle's own allowance is spent only once every other check has passed and the file
	// is actually about to be served, mirroring how pubApiFolderZip meters the bundle.
	if savedFile.BundleId != "" && database.IsShareRestricted(models.ShareResourceBundle, savedFile.BundleId) {
		if !consumeShareDownload(r, models.ShareResourceBundle, savedFile.BundleId) {
			if err := logging.LogDownloadDenied(savedFile, r, configuration.Get().SaveIp,
				"bundle download allowance exhausted"); err != nil {
				respondAuditWriteFailed(w)
				return
			}
			if isRootUrl {
				redirectOnIncorrectId(w, r, "error")
			} else {
				redirectOnIncorrectId(w, r, "../../error")
			}
			return
		}
	}
	validFile := storage.ServeFile(savedFile, w, r, true, true, false, true)
	if !validFile {
		// Called if the file has expired or its download allowance was exhausted, checked
		// during storage.ServeFile()
		if err := logging.LogDownloadDenied(savedFile, r, configuration.Get().SaveIp, "link expired or download allowance exhausted"); err != nil {
			respondAuditWriteFailed(w)
			return
		}
		if isRootUrl {
			redirectOnIncorrectId(w, r, "error")
		} else {
			redirectOnIncorrectId(w, r, "../../error")
		}
		return
	}
}

// Handling of /pubapi/file
// Public, unauthenticated endpoint that returns file metadata as JSON.
// These endpoints are intentionally public to enable standalone client SPAs to drive the UI.
func pubApiFileMetadata(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	keyId := queryUrl(w, r, "id", errorHandling.TypeFileNotFound)
	if keyId == "" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "{\"error\":\"not found\"}")
		return
	}

	file, ok := storage.GetFile(keyId)
	if !ok || file.IsFileRequest() {
		respondPubApiNotFound(w, r)
		return
	}

	// Determine downloads remaining: -1 for unlimited, otherwise the actual count
	downloadsRemaining := file.DownloadsRemaining
	if file.UnlimitedDownloads {
		downloadsRemaining = -1
	}

	// Determine expiry: 0 if unlimited, otherwise the unix timestamp
	expiresAt := file.ExpireAt
	if file.UnlimitedTime {
		expiresAt = 0
	}

	accessMode := shareAccessMode(file)
	// An identity-restricted file exchanges a token in the URL for a cookie
	// here, so a recipient arriving from the mailed link is recognised before
	// the page has made any other request.
	isAuthorisedRecipient := accessMode != models.AccessModeIdentity ||
		recipientFor(w, r, models.ShareResourceFile, keyId) != 0
	// A file that is a member of a restricted bundle carries no grant of its own; the
	// bundle's recipient ACL must cascade here too, or holding the member's individual file id
	// would bypass the bundle restriction and leak its metadata. This is additive to the
	// file's own restriction check above, not a replacement for it.
	if file.BundleId != "" && database.IsShareRestricted(models.ShareResourceBundle, file.BundleId) {
		isAuthorisedRecipient = isAuthorisedRecipient && mayAccessShare(w, r, models.ShareResourceBundle, file.BundleId)
	}

	// The filename is withheld until the caller has proved it may have the
	// file. It is health-adjacent, so leaking it to anyone holding the ID
	// would defeat the point of restricting the file at all.
	restrictedNonRecipient := (file.PasswordHash != "" && !isValidPwCookie(r, file)) || !isAuthorisedRecipient
	name := file.Name
	contentType := file.ContentType
	if restrictedNonRecipient {
		name = ""
		contentType = ""
	}

	response := map[string]interface{}{
		"id":   keyId,
		"name": name,
		// accessMode is the single value a client branches on:
		// "public", "passcode" or "identity". requiresPassword is kept for
		// clients written before it existed.
		"accessMode":               accessMode,
		"requiresPassword":         file.PasswordHash != "",
		"isAuthorised":             isAuthorisedRecipient,
		"isE2E":                    file.Encryption.IsEndToEndEncrypted,
		"requiresClientDecryption": file.RequiresClientDecryption(),
		"contentType":              contentType,
	}
	// size, expiresAt and downloadsRemaining are withheld for the same caller
	// the name and contentType above are withheld from. Without this a caller
	// that merely holds the ID, but has proved neither a password nor a
	// recipient grant, still learned everything about the file except its name
	// - serveFile and the pubApiFolder* handlers already refuse such a caller
	// outright, and this endpoint must not be the one door on this ID that
	// leaks the rest.
	if !restrictedNonRecipient {
		response["size"] = file.Size
		response["expiresAt"] = expiresAt
		response["downloadsRemaining"] = downloadsRemaining
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Handling of /pubapi/filepassword
// Public, unauthenticated endpoint that verifies a password for a file.
// On success, sets the same cookie that showDownload sets.
func pubApiFilePassword(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	keyId := queryUrl(w, r, "id", errorHandling.TypeFileNotFound)
	if keyId == "" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "{\"error\":\"not found\"}")
		return
	}

	file, ok := storage.GetFile(keyId)
	if !ok || file.IsFileRequest() {
		respondPubApiNotFound(w, r)
		return
	}

	// Parse password from body (support both form and JSON)
	var password string
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var body struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			password = body.Password
		}
	} else {
		_ = r.ParseForm()
		password = r.PostForm.Get("password")
	}
	// Trim to match ValidateSharePassword, which trims before hashing whatever value was
	// used to protect the share. Without this, a password set with surrounding whitespace
	// (e.g. "  Trim12Chars!  ") would store the hash of the trimmed value, and the exact
	// string the uploader typed would then fail verification here - only the trimmed form
	// would ever unlock it.
	password = strings.TrimSpace(password)

	// Rate limit the password check attempt
	ip := logging.GetIpAddress(r)
	ratelimiter.WaitOnDownloadPassword(ip)

	// Verify password using the same logic as showDownload
	isValid, isLegacy := configuration.VerifyPassword(password, file.PasswordHash, configuration.Get().Authentication.SaltFiles)
	if isValid {
		// Migrate legacy passwords to the new format
		if isLegacy {
			file.PasswordHash = configuration.HashPassword(password, false, "")
			database.SaveMetaData(file)
		}
		writeFilePwCookie(w, file)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"ok\":true}")
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "{\"ok\":false}")
}

// Handling of /pubapi/uploadrequest
// Public, unauthenticated endpoint that returns file request metadata as JSON.
// These endpoints are intentionally public to enable standalone client SPAs to drive the UI.
func pubApiUploadRequest(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	requestId := queryUrl(w, r, "id", errorHandling.TypeInvalidFileRequest)
	if requestId == "" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "{\"error\":\"not found\"}")
		return
	}

	request, ok := filerequest.Get(requestId)
	if !ok {
		respondPubApiNotFound(w, r)
		return
	}

	if database.IsShareRestricted(models.ShareResourceFileRequest, requestId) {
		// A request mailed to named recipients supersedes the apikey header: everyone holding
		// the link has that same header value, so it must not double as identity here, or the
		// recipient list restricts nothing. recipientFor checks a sharetoken header, a ?token=
		// query param fallback, or an existing cookie, and on a token exchanges it for a cookie.
		if recipientFor(w, r, models.ShareResourceFileRequest, requestId) == 0 {
			// An unthrottled fast 200 next to every other refusal's slow 404 would itself be an
			// existence oracle for restricted request ids, and token guessing must not be free.
			ratelimiter.WaitOnFailedId(r)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{\"valid\":false,\"reason\":\"identity\"}")
			return
		}
	} else {
		apiKey := r.Header.Get("apikey")
		if apiKey == "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "{\"error\":\"not found\"}")
			return
		}

		// Validate the API key using constant-time comparison
		if subtle.ConstantTimeCompare([]byte(request.ApiKey), []byte(apiKey)) != 1 {
			respondPubApiNotFound(w, r)
			return
		}
	}

	// Check if the request is expired
	if !request.IsUnlimitedTime() && request.Expiry < time.Now().Unix() {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"valid\":false,\"reason\":\"expired\"}")
		return
	}

	// A receipt of what this request has already collected, so someone returning to the link
	// can see what they sent before instead of an empty page. Names and sizes only: no file id
	// and no download route, so this cannot be turned into a way to retrieve the contents.
	// Everyone holding the link sees the same list - a request link is a shared address, not a
	// per-person identity.
	receivedFiles := make([]map[string]interface{}, 0, len(request.Files))
	sortedFiles := make([]models.File, len(request.Files))
	copy(sortedFiles, request.Files)
	// Newest first, then by name, since Populate builds this from a map and has no order.
	sort.Slice(sortedFiles, func(i, j int) bool {
		if sortedFiles[i].UploadDate != sortedFiles[j].UploadDate {
			return sortedFiles[i].UploadDate > sortedFiles[j].UploadDate
		}
		return sortedFiles[i].Name < sortedFiles[j].Name
	})
	for _, file := range sortedFiles {
		receivedFiles = append(receivedFiles, map[string]interface{}{
			"name":       file.Name,
			"sizeBytes":  file.SizeBytes,
			"uploadDate": file.UploadDate,
		})
	}

	// Marked complete, by the owner or by a link holder. Reported ahead of the max-files check
	// because it is the deliberate decision and the file count is only incidental, and it carries
	// the same receipt: being told a request is finished is exactly when someone wants to confirm
	// what they sent actually arrived.
	if request.Closed {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":         false,
			"reason":        "closed",
			"receivedFiles": receivedFiles,
		})
		return
	}

	// Check if the request has reached max files
	if !request.IsUnlimitedFiles() && request.UploadedFiles >= request.MaxFiles {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":         false,
			"reason":        "full",
			"receivedFiles": receivedFiles,
		})
		return
	}

	// Calculate remaining files
	remainingFiles := request.MaxFiles - request.UploadedFiles
	if request.IsUnlimitedFiles() {
		remainingFiles = -1
	}

	config := configuration.Get()

	response := map[string]interface{}{
		"valid":          true,
		"name":           request.DisplayName(),
		"notes":          request.Notes,
		"maxFiles":       request.MaxFiles,
		"remainingFiles": remainingFiles,
		"maxSizeMB":      request.MaxSize,
		"chunkSize":      config.ChunkSize,
		"expiry":         request.Expiry,
		"receivedFiles":  receivedFiles,
		// The SPA's chunked guest-upload endpoints (/api/uploadrequest/chunk/*) authenticate
		// with this key. A mailed recipient never had it, so an authorised caller is handed
		// exactly what every other link holder already carries in the URL - in the JSON body,
		// not a URL, so it never lands in access logs.
		"apikey": request.ApiKey,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Handling of /pubapi/folder
// Public, unauthenticated endpoint that returns folder metadata as JSON.
func pubApiFolder(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	folderId := queryUrl(w, r, "id", errorHandling.TypeFileNotFound)
	if folderId == "" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "{\"error\":\"not found\"}")
		return
	}

	bundle, ok := filebundle.Get(folderId)
	if !ok {
		respondPubApiNotFound(w, r)
		return
	}

	// An identity-restricted bundle is refused as "not found", the same convention
	// serveFile uses for a restricted file: a 200 with requiresPassword/etc would
	// still confirm the id names a real bundle to anyone probing it.
	if !mayAccessShare(w, r, models.ShareResourceBundle, bundle.Id) {
		respondPubApiNotFound(w, r)
		return
	}

	// Get all files, then narrow to the requester's own true membership - every
	// non-deleted, non-file-request member of the bundle it may individually access - not
	// yet filtered by servability. A member can carry its own, separate restriction
	// independent of the bundle's.
	allFiles := database.GetAllMetadata()
	memberFiles := accessibleBundleMembers(w, r, bundleMembers(bundle.Id, allFiles))

	// A bundle that cannot be served in full - no members at all, or any member expired or
	// exhausted - must be indistinguishable from one that never existed: no name, and no
	// password-protection status, revealed. This is checked before isProtected is computed
	// and before the password gate below, precisely because scanning only the servable
	// subset for a password hash would otherwise report a protected-but-fully-expired
	// folder as unprotected. See bundleAvailability.
	//
	// Answers exactly as an unknown id does, rather than with a distinct "gone" status: a
	// folder that cannot be served must be indistinguishable from one that never existed,
	// which is already how a single expired file behaves (storage.GetFile refuses it and the
	// caller 404s). A separate status would also skip respondPubApiNotFound's
	// ratelimiter.WaitOnFailedId, so the two cases would differ in timing as well as in code -
	// and mayAccessShare proves nothing for an unrestricted bundle, where it returns true
	// without any check at all.
	if !bundleAvailability(memberFiles) {
		respondPubApiNotFound(w, r)
		return
	}

	// Check if folder is password protected (ANY member has a password)
	isProtected := false
	for _, file := range memberFiles {
		if file.PasswordHash != "" {
			isProtected = true
			break
		}
	}

	// Handle password protection
	if isProtected && !isValidPwCookieBundle(r, bundle) {
		response := map[string]interface{}{
			"id":               folderId,
			"requiresPassword": true,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Return full folder metadata
	type FileMetadata struct {
		Id          string `json:"id"`
		Name        string `json:"name"`
		SizeBytes   int64  `json:"sizeBytes"`
		Size        string `json:"size"`
		ContentType string `json:"contentType"`
	}

	files := make([]FileMetadata, 0)
	for _, file := range memberFiles {
		files = append(files, FileMetadata{
			Id:          file.Id,
			Name:        file.Name,
			SizeBytes:   file.SizeBytes,
			Size:        file.Size,
			ContentType: file.ContentType,
		})
	}

	response := map[string]interface{}{
		"id":               folderId,
		"name":             bundle.DisplayName(),
		"requiresPassword": isProtected,
		"files":            files,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Handling of /pubapi/folderpassword
// Public, unauthenticated endpoint that verifies a password for a folder.
func pubApiFolderPassword(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	folderId := queryUrl(w, r, "id", errorHandling.TypeFileNotFound)
	if folderId == "" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "{\"error\":\"not found\"}")
		return
	}

	bundle, ok := filebundle.Get(folderId)
	if !ok {
		respondPubApiNotFound(w, r)
		return
	}

	// See the identical check in pubApiFolder: a restricted bundle is refused as
	// "not found" for a non-authorised requester, before anything about it - even
	// whether it is password protected - is revealed.
	if !mayAccessShare(w, r, models.ShareResourceBundle, bundle.Id) {
		respondPubApiNotFound(w, r)
		return
	}

	// Get all files and find all servable members that have a password
	allFiles := database.GetAllMetadata()
	members := accessibleBundleMembers(w, r, servableBundleMembers(bundle.Id, allFiles))
	var passwordFiles []models.File
	for _, file := range members {
		if file.PasswordHash != "" {
			passwordFiles = append(passwordFiles, file)
		}
	}

	if len(passwordFiles) == 0 {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"ok\":false}")
		return
	}

	// Parse password from body (support both form and JSON)
	var password string
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var body struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			password = body.Password
		}
	} else {
		_ = r.ParseForm()
		password = r.PostForm.Get("password")
	}
	// Trim to match ValidateSharePassword - see the identical comment in pubApiFilePassword.
	password = strings.TrimSpace(password)

	// Rate limit the password check attempt
	ip := logging.GetIpAddress(r)
	ratelimiter.WaitOnDownloadPassword(ip)

	// Verify password against EVERY protected member
	allValid := true
	var migratedFiles []models.File
	for i, file := range passwordFiles {
		isValid, isLegacy := configuration.VerifyPassword(password, file.PasswordHash, configuration.Get().Authentication.SaltFiles)
		if !isValid {
			allValid = false
			break
		}
		// Migrate legacy passwords to the new format
		if isLegacy {
			file.PasswordHash = configuration.HashPassword(password, false, "")
			migratedFiles = append(migratedFiles, file)
			passwordFiles[i] = file
		}
	}

	if !allValid {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"ok\":false}")
		return
	}

	// Save any migrated passwords
	for _, file := range migratedFiles {
		database.SaveMetaData(file)
	}

	writeFolderPwCookie(w, bundle)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "{\"ok\":true}")
}

// Handling of /pubapi/folderzip
// Public, unauthenticated endpoint that serves folder files as a zip or single file raw.
func pubApiFolderZip(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)

	folderId := queryUrl(w, r, "id", errorHandling.TypeFileNotFound)
	if folderId == "" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "{\"error\":\"not found\"}")
		return
	}

	bundle, ok := filebundle.Get(folderId)
	if !ok {
		respondPubApiNotFound(w, r)
		return
	}

	// See the identical check in pubApiFolder: a restricted bundle is refused as
	// "not found" for a non-authorised requester, before any bytes are served.
	if !mayAccessShare(w, r, models.ShareResourceBundle, bundle.Id) {
		respondPubApiNotFound(w, r)
		return
	}

	// Get all files once, do exactly one database scan
	allFiles := database.GetAllMetadata()

	// Check password gate
	if !isValidFolderPassword(w, r, bundle, allFiles) {
		return
	}

	// Parse ids parameter (optional; absent = every member)
	idsParam := r.URL.Query().Get("ids")
	var requestedIds []string
	if idsParam != "" {
		requestedIds = strings.Split(idsParam, ",")
	}

	// Resolve the requester's full true membership - not yet narrowed by servability - the
	// same set pubApiFolder uses, so the two endpoints agree on what "a member of this
	// bundle" means. A member can carry its own restriction independent of the bundle's.
	members := accessibleBundleMembers(w, r, bundleMembers(bundle.Id, allFiles))

	// Narrow to the requested set: either the explicit ids, validated as true members of
	// this bundle, or every member. Membership is checked against the full true set, not a
	// servability-narrowed one, so requesting the id of a member that merely happens to be
	// expired still reaches the "refuse the whole request" check below instead of a
	// confusing 400.
	var requestedMembers []models.File
	if len(requestedIds) > 0 {
		for _, requestedId := range requestedIds {
			found := false
			for _, file := range members {
				if file.Id == requestedId {
					found = true
					if !file.RequiresClientDecryption() {
						requestedMembers = append(requestedMembers, file)
					}
					break
				}
			}
			if !found {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
	} else {
		for _, file := range members {
			if file.RequiresClientDecryption() {
				continue
			}
			requestedMembers = append(requestedMembers, file)
		}
	}

	if len(requestedMembers) == 0 {
		respondPubApiNotFound(w, r)
		return
	}

	// Refuse the whole request rather than silently narrow it: a folder zip that omits an
	// expired or exhausted member looks like a complete archive and is not. With per-file
	// download counters still in place, a bundle (or the requested subset of it) is only
	// servable as a unit if every member requested is. Rechecked fresh here rather than
	// trusting the allFiles snapshot, since it may already be stale by the time of the
	// request.
	timeNow := time.Now().Unix()
	for _, file := range requestedMembers {
		if !file.UnlimitedDownloads {
			file.DownloadsRemaining = database.GetDownloadsRemaining(file.Id)
		}
		if storage.IsExpiredFile(file, timeNow) {
			respondPubApiNotFound(w, r)
			return
		}
	}

	// The bundle download as a whole is metered once per request, not once per member,
	// since the restriction and the allowance are on the bundle. Checked and consumed
	// first, before any member's own counter is touched, so an exhausted bundle allowance
	// never burns a member's own allowance for a file that is never delivered.
	if !consumeShareDownload(r, models.ShareResourceBundle, bundle.Id) {
		respondPubApiNotFound(w, r)
		return
	}

	// Serve single file raw, or multiple files as zip. Every member of requestedMembers is
	// guaranteed servable at this point (checked above), so reaching this branch with
	// exactly one never means filtering silently narrowed a larger set down to one - it
	// means the caller explicitly asked for one id, or the bundle's true membership is
	// exactly one member to begin with.
	if len(requestedMembers) == 1 {
		file := requestedMembers[0]
		// A member that is itself identity-restricted spends its own recipient
		// allowance, same as a direct single-file download would.
		if !consumeShareDownload(r, models.ShareResourceFile, file.Id) {
			respondPubApiNotFound(w, r)
			return
		}
		// Serve raw file
		serveBundleFile(w, r, file)
		return
	}

	// Serve as zip - folder downloads meter every member by rechecking expiry and
	// atomically consuming one download before streaming each member. This is a race-only
	// backstop: the availability check above already confirmed every requested member is
	// servable moments earlier, using a fresh read, so this loop is only expected to
	// exclude a member on a download that lands in the narrow window between that check and
	// this one - not as the mechanism that decides whether the archive is complete.
	filesToServeInZip := make([]models.File, 0, len(requestedMembers))
	for _, file := range requestedMembers {
		// Recheck expiry and atomically consume one download, reusing the same primitives ServeFile uses
		if !file.UnlimitedDownloads {
			file.DownloadsRemaining = database.GetDownloadsRemaining(file.Id)
		}
		if storage.IsExpiredFile(file, time.Now().Unix()) {
			// This member has expired; exclude it from the archive
			continue
		}
		if !file.UnlimitedDownloads {
			if !database.IncreaseDownloadCount(file.Id, true) {
				// Atomic, floored decrement lost the race (or found the allowance already exhausted);
				// exclude this member from the archive
				continue
			}
		} else {
			database.IncreaseDownloadCount(file.Id, false)
		}
		// A member that is itself identity-restricted also spends its own
		// recipient allowance; exclude it from the archive like any other
		// exhausted member rather than failing the whole zip.
		if !consumeShareDownload(r, models.ShareResourceFile, file.Id) {
			continue
		}
		filesToServeInZip = append(filesToServeInZip, file)
	}

	if len(filesToServeInZip) == 0 {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "{\"error\":\"not found\"}")
		return
	}

	// Serve as zip - keep the audit logging that ServeFilesAsZip already performs per entry
	storage.ServeFilesAsZip(filesToServeInZip, bundle.Name, w, r)
}

// Serve a single file from a bundle with proper headers and decryption
// Returns true if successfully served, false if download was denied (expired or exhausted).
func serveBundleFile(w http.ResponseWriter, r *http.Request, file models.File) {
	// Use ServeFile with forceDownload=true to set attachment headers and serve the file
	// increaseCounter=true to decrement download counter (matches the /d door behavior)
	// forceDecryption=false to handle decryption normally
	// recheckExpiry=true to verify expiry at serve time
	validFile := storage.ServeFile(file, w, r, true, true, false, true)
	if !validFile {
		// Called if the file has expired or its download allowance was exhausted, checked
		// during storage.ServeFile()
		if err := logging.LogDownloadDenied(file, r, configuration.Get().SaveIp, "link expired or download allowance exhausted"); err != nil {
			respondAuditWriteFailed(w)
			return
		}
	}
}

// bundleMembers returns every file that belongs to a bundle for listing/serving purposes -
// not pending for deletion, not a file request upload - regardless of whether it is currently
// servable. Servability (expired, or its download allowance exhausted) is deliberately not
// folded in here: a caller that conflates "is a member" with "is currently servable" ends up
// treating a bundle with some dead members as if those members never existed at all, which is
// exactly the silent-partial-archive and password-gate-skipping bugs this split exists to
// prevent. Use servableBundleMembers for the narrowed set, or bundleAvailability to decide
// whether the whole bundle can be served at all.
func bundleMembers(bundleId string, allFiles map[string]models.File) []models.File {
	var result []models.File
	for _, file := range allFiles {
		if file.BundleId == bundleId &&
			!file.IsPendingForDeletion() &&
			!file.IsFileRequest() {
			result = append(result, file)
		}
	}
	return result
}

// servableBundleMembers narrows bundleMembers to the ones that are also currently servable.
// Only safe to use once a bundle has already been confirmed available in full - see
// bundleAvailability - since silently dropping the unservable members here is exactly what
// must not happen when deciding whether to respond at all.
func servableBundleMembers(bundleId string, allFiles map[string]models.File) []models.File {
	var result []models.File
	timeNow := time.Now().Unix()
	for _, file := range bundleMembers(bundleId, allFiles) {
		if !storage.IsExpiredFile(file, timeNow) {
			result = append(result, file)
		}
	}
	return result
}

// bundleAvailability reports whether every one of the given members - the requester's full,
// access-filtered bundle membership - is currently servable. A bundle with no members, or
// with even one member expired or its download allowance exhausted, is not available: with
// per-file download counters still in place, a partially dead bundle cannot be told apart
// from a complete one from the outside, so the whole of it is refused rather than silently
// narrowed to whatever remains. See bundleMembers.
func bundleAvailability(members []models.File) bool {
	if len(members) == 0 {
		return false
	}
	timeNow := time.Now().Unix()
	for _, file := range members {
		if storage.IsExpiredFile(file, timeNow) {
			return false
		}
	}
	return true
}

// Check if folder is password protected and if a valid cookie exists
func isValidFolderPassword(w http.ResponseWriter, r *http.Request, bundle models.FileBundle, allFiles map[string]models.File) bool {
	// Checked against the full true membership, not just the currently-servable subset: a
	// bundle whose only protected member has since expired must still be recognised as
	// having been protected, the same reasoning as pubApiFolder's isProtected check.
	members := accessibleBundleMembers(w, r, bundleMembers(bundle.Id, allFiles))
	isProtected := false
	for _, file := range members {
		if file.PasswordHash != "" {
			isProtected = true
			break
		}
	}

	if !isProtected {
		return true
	}

	if isValidPwCookieBundle(r, bundle) {
		return true
	}

	// Password protection required, no valid cookie
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	response := map[string]interface{}{
		"id":               bundle.Id,
		"requiresPassword": true,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	return false
}

// Helper function to check if a valid password cookie exists for a bundle
func isValidPwCookieBundle(r *http.Request, bundle models.FileBundle) bool {
	cookie, err := r.Cookie("b" + bundle.Id)
	if err != nil {
		return false
	}
	return downloadPasswordToken.IsValid(cookie.Value, "bundle:"+bundle.Id)
}

// Helper function to write a password cookie for a bundle
func writeFolderPwCookie(w http.ResponseWriter, bundle models.FileBundle) {
	http.SetCookie(w, &http.Cookie{
		Name:     "b" + bundle.Id,
		Value:    downloadPasswordToken.Generate("bundle:" + bundle.Id),
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
		Secure:   configuration.UsesHttps(),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}

// Handling of /pubapi/error
// Public, unauthenticated endpoint that resolves the "e" token on an /error URL
// into JSON, so a standalone SPA can render the failure in its own design.
//
// The copy lives here rather than in the client because the stock /error
// template already owns it, and two copies of an error taxonomy drift: a new
// generic type added to errorHandling would silently render as a blank card in
// the SPA. The client decides only how it looks, never what it says.
//
// This matters most with the built-in UI disabled. /error still resolves (the
// download endpoints redirect to it), but without the stock CSS, and in an SPA
// deployment the reverse proxy answers /error with the app shell instead. A
// failed OAuth login would otherwise land on a route the SPA does not know and
// be swallowed by its catch-all redirect, turning a stated reason into a
// silent bounce back to the file list.
func pubApiError(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	// Error tokens are single-use in practice and expire after five minutes, so
	// a cached response would outlive the thing it describes.
	w.Header().Set("Cache-Control", "no-store")

	displayed := errorHandling.Get(r)

	title := displayed.Title
	message := displayed.Message
	// Offering "log in as a different user" only makes sense when the failure
	// was an identity decision. On a dead download link it would invite a
	// login that cannot change the outcome.
	canRetryLogin := false

	if displayed.IsGeneric {
		switch displayed.ErrorId {
		case errorHandling.TypeFileNotFound:
			title = "File not found"
			message = "The link may have expired or the file has been downloaded too many times."
		case errorHandling.TypeInvalidFileRequest:
			title = "Unable to upload files"
			message = "The upload request has expired, its file limit has been reached, or the URL is not valid."
		case errorHandling.TypeE2ECipher:
			title = "Missing or invalid decryption key"
			message = "This file is encrypted, but no key was provided or the key is invalid. Ask the sender for the complete link, including the part after the # symbol."
		case errorHandling.TypeOAuthNotAuthorised:
			title = "Unauthorised user"
			message = "Sign-in with the identity provider succeeded, but this account is not permitted to use this server."
			canRetryLogin = true
		}
	} else if displayed.ErrorId == errorHandling.TypeOAuthNonGeneric {
		if title == "" {
			title = "Sign-in failed"
		}
		canRetryLogin = true
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"title":   title,
		"message": message,
		// The provider's own wording, kept separate so the client can present
		// it as quoted machine output rather than as this server's prose.
		"providerMessage": displayed.OAuthProviderMessage,
		"canRetryLogin":   canRetryLogin,
	})
}

// Handling of /pubapi/config
// Public, unauthenticated endpoint that returns non-sensitive configuration values as JSON.
// Used by standalone client SPAs to determine server behavior and capabilities.
func pubApiConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Cache-Control", "public, max-age=300")

	config := configuration.Get()
	env := configuration.GetEnvironment()

	// Determine auth methods
	authConfig := config.Authentication
	isHybrid := authConfig.Method == models.AuthenticationInternal && authConfig.OAuthEnabledAlongsideInternal
	isInternal := authConfig.Method == models.AuthenticationInternal || isHybrid
	isOAuth := authConfig.Method == models.AuthenticationOAuth2 || (isHybrid && oauth.IsAvailable())

	// Determine oauthProvider label
	oauthProviderLabel := "SSO"
	if strings.Contains(authConfig.OAuthProvider, "accounts.google.com") {
		oauthProviderLabel = "Google"
	}

	// Determine if hotlinks are enabled globally
	// Hotlinks are disabled if: DisableHotlinks flag is set (env-level gate)
	// File-level gates (RequiresClientDecryption, password, content type) are checked per-file by storage.IsAbleHotlink
	// DisableBuiltinUI also disables them, since /h/ is the only door hotlinks are served
	// through and it is not registered then; advertising the feature would let clients
	// create hotlinks whose URLs can never resolve
	hotlinksEnabled := !env.DisableHotlinks && !env.DisableBuiltinUI

	response := map[string]interface{}{
		"publicName": config.PublicName,
		"auth": map[string]interface{}{
			"internal":      isInternal,
			"oauth":         isOAuth,
			"oauthProvider": oauthProviderLabel,
		},
		"features": map[string]interface{}{
			"folders":       true,
			"fileRequests":  true,
			"e2eEncryption": config.Encryption.Level == encryption.EndToEndEncryption,
			"hotlinks":      hotlinksEnabled,
			// Sharing to a list of email addresses depends on being able to
			// mail each recipient their access link. With no mail connector
			// configured there is no way to deliver one, so the option is
			// reported as unavailable and the interface hides it, rather than
			// letting an uploader create a share nobody can ever reach.
			"emailRecipients": mail.IsEnabled(),
		},
		"limits": map[string]interface{}{
			"maxFileSizeMB":      config.MaxFileSizeMB,
			"chunkSizeMB":        config.ChunkSize,
			"maxParallelUploads": config.MaxParallelUploads,
			"minPasswordLength":  env.MinLengthPassword,
			// maxExpirySeconds is 0 if no maximum is configured (GOKAPI_MAX_EXPIRY unset), the
			// same "0 means uncapped" convention used throughout this API for expiry values.
			"maxExpirySeconds":     int64(time.Duration(env.MaxExpiry).Seconds()),
			"expiryOptionsSeconds": expiryOptionsSeconds(env.ExpiryOptions),
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// expiryOptionsSeconds converts environment.Environment.ExpiryOptions (already validated and
// sorted by environment.New) to whole seconds for the client, which works in Unix timestamps.
func expiryOptionsSeconds(options []environment.Duration) []int64 {
	result := make([]int64, len(options))
	for i, opt := range options {
		result[i] = int64(time.Duration(opt).Seconds())
	}
	return result
}

// respondAuditWriteFailed refuses a request whose audit record could not be committed to
// durable local storage. The fail-closed design requires that the caller not proceed after
// calling this - not serve file content, not reveal whether a denial was due to a wrong
// password or an expired/exhausted link, nothing - since none of that would be recorded.
func respondAuditWriteFailed(w http.ResponseWriter) {
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("Service temporarily unavailable, please try again."))
}

func requireLogin(next http.HandlerFunc, isUiCall, isPwChangeView bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addNoCacheHeader(w)
		user, isLoggedIn, err := authentication.IsAuthenticated(w, r)
		if err != nil {
			errorHandling.RedirectToErrorPage(w, r, "Unable to log in", "The following error was raised: "+err.Error(), errorHandling.WidthDefault)
			return
		}
		if isLoggedIn {
			// Force password change for internal auth users only, never for an OAuth-provisioned
			// user - checking user.AuthProvider directly (rather than the configured
			// authentication method) is what makes this correct in every mode: internal-only
			// (every user is AuthProviderInternal), OAuth2-only (every user is
			// AuthProviderGoogle, see getOrCreateUser), and hybrid (mixed). A prior version of
			// this condition also allowed on authConfig.Method == models.AuthenticationInternal,
			// which is true in hybrid mode by definition and made the AuthProvider check
			// unreachable, forcing OAuth-provisioned users in hybrid mode into changePassword.
			if user.ResetPassword && isUiCall && user.AuthProvider == models.AuthProviderInternal {
				if !isPwChangeView {
					redirect(w, r, "changePassword")
					return
				}
			}
			r = authentication.SetUserInRequest(r, user)
			next.ServeHTTP(w, r)
			return
		}
		if !isUiCall {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			_, _ = io.WriteString(w, "{\"Result\":\"error\",\"ErrorMessage\":\"Not authenticated\"}")
			return
		}
		redirect(w, r, "login")
	}
}

type adminButtonContext struct {
	CurrentFile models.FileApiOutput
	ActiveUser  *models.User
}

// Used internally in templates to create buttons with user context
func newAdminButtonContext(file models.FileApiOutput, user models.User) adminButtonContext {
	return adminButtonContext{CurrentFile: file, ActiveUser: &user}
}

// Write a cookie if the user has entered a correct password for a password-protected file
func writeFilePwCookie(w http.ResponseWriter, file models.File) {
	http.SetCookie(w, &http.Cookie{
		Name:     "p" + file.Id,
		Value:    downloadPasswordToken.Generate(file.Id),
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
		Secure:   configuration.UsesHttps(),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}

// Checks if a cookie contains the correct token for a password-protected file
func isValidPwCookie(r *http.Request, file models.File) bool {
	cookie, err := r.Cookie("p" + file.Id)
	if err != nil {
		return false
	}
	return downloadPasswordToken.IsValid(cookie.Value, file.Id)
}

// Adds a header to disable external caching
func addNoCacheHeader(w http.ResponseWriter) {
	w.Header().Set("cdn-cache-control", "no-store, no-cache")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store, no-cache")
	w.Header().Set("cache-control", "no-store, no-cache")
	w.Header().Set("Pragma", "no-cache")
}

func addCacheHeader(w http.ResponseWriter) {
	w.Header().Set("cdn-cache-control", "public, max-age=36000")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "public, max-age=36000")
	w.Header().Set("cache-control", "public, max-age=36000")
}

// A view containing parameters for a generic template
type genericView struct {
	IsAdminView       bool
	IsDownloadView    bool
	IsGenericError    bool
	PublicName        string
	RedirectUrl       string
	ErrorTitle        string
	ErrorMessage      string
	ErrorOauthMessage string
	CsrfToken         string
	ErrorCardWidth    string
	ErrorId           int
	MinPasswordLength int
	CustomContent     customStatic
}

// A view containing parameters for an oauth error
type oauthErrorView struct {
	IsAdminView          bool
	IsDownloadView       bool
	PublicName           string
	IsAuthDenied         bool
	ErrorGenericMessage  string
	ErrorProvidedName    string
	ErrorProvidedMessage string
	CustomContent        customStatic
}

// A view containing parameters for the public upload page
type publicUploadView struct {
	IsAdminView    bool
	IsDownloadView bool
	PublicName     string
	ChunkSize      int
	MaxServerSize  int
	PrivacyNotice  string
	CustomContent  customStatic
	FileRequest    *models.FileRequest
}

// Handling of /pubapi/share/resend
// Public, unauthenticated endpoint that mails a recipient a fresh access link
// for one resource, for when the first one was lost.
//
// Every outcome returns the SAME response, including a cooldown hit. An
// unknown address, an address with no grant on this resource, a blocked
// recipient, an unrestricted resource and a too-recent previous send must all
// be indistinguishable, or this endpoint becomes a way to ask "was this
// person sent this file" - exactly the fact the feature exists to protect.
// The cooldown is only ever reached after the grant check passes, so
// surfacing it as a distinct response (as a previous version of this handler
// did, with a 429) would itself leak recipient status across two requests. A
// genuine double-click is left for the client to debounce.
func pubApiShareResend(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeader(w)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = io.WriteString(w, `{"error":"method not allowed"}`)
		return
	}

	// This handler can trigger a mail send and retire a recipient's live link,
	// so - like every other /pubapi/* path - an anonymous caller must not be
	// able to hammer it without limit.
	ratelimiter.WaitOnFailedId(r)

	var request struct {
		ResourceType int    `json:"resourceType"`
		ResourceId   string `json:"resourceId"`
		Email        string `json:"email"`
	}
	const maxBodySize = 8 * 1024
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid request"}`)
		return
	}

	// A uniform acknowledgement, sent whatever actually happened below.
	respondAccepted := func() {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"result":"OK"}`)
	}

	if request.ResourceId == "" || request.Email == "" ||
		!models.IsValidShareResourceType(request.ResourceType) {
		respondAccepted()
		return
	}

	resource, ok := describeShareResource(request.ResourceType, request.ResourceId)
	if !ok {
		respondAccepted()
		return
	}

	_ = shareaccess.ResendLink(resource, request.Email,
		configuration.Get().ServerUrl, logging.GetIpAddress(r))
	respondAccepted()
}

// describeShareResource looks up a resource for the public resend path. Unlike
// the admin equivalent it performs no ownership check, because the caller is
// anonymous; authorisation is the grant check inside ResendLink.
//
// A resource that cannot currently be served - expired, exhausted, closed, or pending
// deletion - is reported exactly like an unknown one. cleanInvalidFileRequests only removes
// a file request once its owning user is gone, never once it expires or is closed, and a
// bundle record likewise outlives its members for a 24h grace period - without this check
// the resend endpoint would keep mailing a valid-looking link to a resource nobody can
// actually reach, for as long as that record happens to still exist. See the doc comment on
// pubApiShareResend for why every outcome, including this one, must stay indistinguishable.
func describeShareResource(resourceType int, resourceId string) (shareaccess.Resource, bool) {
	switch resourceType {
	case models.ShareResourceFile:
		// storage.GetFile already refuses a file that is expired, exhausted, pending
		// deletion, or otherwise unservable - the same check the public file endpoint
		// relies on to 404 for a dead file, reused here for the same reason.
		file, found := storage.GetFile(resourceId)
		if !found {
			return shareaccess.Resource{}, false
		}
		expiry := file.ExpireAt
		if file.UnlimitedTime {
			expiry = 0
		}
		return shareaccess.Resource{Type: resourceType, Id: resourceId, Name: file.Name, ExpiresAt: expiry}, true
	case models.ShareResourceBundle:
		bundle, found := database.GetFileBundle(resourceId)
		if !found {
			return shareaccess.Resource{}, false
		}
		// Same rule the public folder endpoints enforce: a bundle is only servable if
		// every one of its members is. See bundleMembers/bundleAvailability.
		if !bundleAvailability(bundleMembers(bundle.Id, database.GetAllMetadata())) {
			return shareaccess.Resource{}, false
		}
		return shareaccess.Resource{Type: resourceType, Id: resourceId, Name: bundle.DisplayName()}, true
	case models.ShareResourceFileRequest:
		fileRequest, found := database.GetFileRequest(resourceId)
		if !found {
			return shareaccess.Resource{}, false
		}
		if fileRequest.Closed || (!fileRequest.IsUnlimitedTime() && fileRequest.Expiry < time.Now().Unix()) {
			return shareaccess.Resource{}, false
		}
		return shareaccess.Resource{Type: resourceType, Id: resourceId,
			Name: fileRequest.DisplayName(), ExpiresAt: fileRequest.Expiry}, true
	default:
		return shareaccess.Resource{}, false
	}
}
