package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/features"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/logging/serverstats"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/storage"
	"github.com/forceu/gokapi/internal/storage/chunking"
	"github.com/forceu/gokapi/internal/storage/chunking/chunkreservation"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/storage/filerequest"
	"github.com/forceu/gokapi/internal/storage/presign"
	"github.com/forceu/gokapi/internal/webserver/api/mutex/apimutex"
	"github.com/forceu/gokapi/internal/webserver/api/mutex/e2emutex"
	"github.com/forceu/gokapi/internal/webserver/authentication/avatar"
	"github.com/forceu/gokapi/internal/webserver/authentication/downloadPasswordToken"
	"github.com/forceu/gokapi/internal/webserver/authentication/users"
	"github.com/forceu/gokapi/internal/webserver/errorHandling/errorcodes"
	"github.com/forceu/gokapi/internal/webserver/fileupload"
	"github.com/forceu/gokapi/internal/webserver/ratelimiter"
)

// LengthPublicId is the length of the public ID used for API keys
const LengthPublicId = 35

// LengthApiKey is the length of the private API key used for authentication
const LengthApiKey = 30

// Process parses the request and executes the API call or returns an error message to the sender
func Process(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("cache-control", "no-store")
	requestUrl := parseRequestUrl(r)

	// Unauthenticated endpoint: /auth/info
	if r.Method == "GET" && requestUrl == "/auth/info" {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		apiAuthInfo(w, nil, models.User{}, models.ApiKey{})
		return
	}

	// Unauthenticated endpoint: /seal-status - see apiSealStatus. Like /auth/info above, this has
	// to be reachable before any session/API key can be verified: at the Input encryption levels
	// there is no key to check anything against until an admin unseals the instance.
	if r.Method == "GET" && requestUrl == "/seal-status" {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		apiSealStatus(w, nil, models.User{}, models.ApiKey{})
		return
	}

	// Unauthenticated endpoint: /unseal - see apiUnseal. Deliberately not routed through the
	// authenticated routes table below: unlike every other endpoint there, this one exists
	// specifically for the case where no key is loaded to authenticate against yet.
	if r.Method == "POST" && requestUrl == "/unseal" {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		apiUnseal(w, r)
		return
	}

	routing, ok := getRouting(requestUrl)
	if !ok {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		sendError(w, http.StatusBadRequest, errorcodes.InvalidUrl, "Invalid request")
		return
	}
	if !routing.NoJsonResponse {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	}
	var user models.User
	var apiKey models.ApiKey
	user, apiKey, ok = isAuthorisedForApi(r, routing)
	if !ok {
		sendError(w, http.StatusUnauthorized, errorcodes.InvalidApiKey, "Unauthorized")
		return
	}
	if routing.AdminOnly && !user.IsAdmin() {
		sendError(w, http.StatusUnauthorized, errorcodes.AdminOnly, "Unauthorized")
		return
	}
	if routing.RequestParser == nil {
		routing.Continue(w, nil, user, apiKey)
		return
	}
	parser := routing.RequestParser.New()
	err := parser.ParseRequest(r)
	if err != nil {
		sendError(w, http.StatusBadRequest, errorcodes.CannotParse, err.Error())
		return
	}
	routing.Continue(w, parser, user, apiKey)
}

func parseRequestUrl(r *http.Request) string {
	return strings.Replace(r.URL.String(), "/api", "", 1)
}

func apiEditFile(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesModify)
	if !ok {
		panic("invalid parameter passed")
	}
	apimutex.Lock(apimutex.TypeMetaData, request.Id)
	defer apimutex.Unlock(apimutex.TypeMetaData, request.Id)

	file, ok := database.GetMetaDataById(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid file ID provided.")
		return
	}
	if file.UserId != user.Id && !user.HasPermission(models.UserPermEditOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to edit file.")
		return
	}

	// A bundle member's password, expiry and download allowance are inert - the bundle owns them
	// now (see models.FileBundle.PasswordHash and friends) - so an edit that would have touched
	// any of them here is refused instead of silently doing nothing. Every field this endpoint
	// currently knows how to change is one of these, so this refuses the whole request for a
	// bundled file; a caller with no actual change requested (every header absent) still no-ops
	// through to the end exactly as before.
	if file.BundleId != "" && (request.IsPasswordSet || request.RemovePassword ||
		request.UnlimitedDownloads || request.AllowedDownloads != 0 ||
		request.UnlimitedExpiry || request.ExpiryTimestamp != 0) {
		sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, "This file belongs to a folder; edit the folder instead.")
		return
	}

	// Validated and hashed up front, before any field of file is touched, so that a
	// rejected password change (too short, or whitespace that trims to nothing) leaves
	// every other requested edit unsaved too, instead of applying a partial update.
	//
	// changePassword is true only when the caller actually sent a "password" header -
	// never merely because a "keep the original" flag was left at its zero value. This
	// mirrors paramFilesDuplicate/apiDuplicateFile exactly: an absent password header
	// always means "do not touch the password", whether that's because the caller wants
	// to keep it or because the caller only meant to change something else entirely
	// (e.g. allowedDownloads). Removal is a separate, explicit signal (RemovePassword)
	// requested through its own header, so it can never happen as the byproduct of an
	// omission - see paramFilesModify.ProcessParameter in routing.go, which also rejects
	// a request that sets both password and removePassword at once.
	changePassword := request.IsPasswordSet
	removePassword := request.RemovePassword
	var newPasswordHash string
	var newSharePassword string
	if changePassword {
		validatedPassword, err := configuration.ValidateSharePassword(request.Password, request.IsPasswordSet)
		if err != nil {
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
			return
		}
		newPasswordHash = configuration.HashPassword(validatedPassword, false, "")
		newSharePassword = validatedPassword
	}

	if request.UnlimitedDownloads {
		file.UnlimitedDownloads = true
	} else {
		if request.AllowedDownloads != 0 {
			file.DownloadsRemaining = request.AllowedDownloads
			file.UnlimitedDownloads = false
		}
	}
	if request.UnlimitedExpiry {
		file.UnlimitedTime = true
	} else {
		if request.ExpiryTimestamp != 0 {
			file.ExpireAt = request.ExpiryTimestamp
			file.UnlimitedTime = false
		}
	}
	// Creation paths are clamped in CreateUploadConfig, but this one writes the expiry
	// directly, so the retention cap has to be applied here too. Clamping after the
	// branches above also catches a file that predates the cap being configured.
	file.ExpireAt, file.UnlimitedTime = fileupload.ClampExpiryTimestamp(file.ExpireAt, file.UnlimitedTime)

	if changePassword {
		file.PasswordHash = newPasswordHash
		// Always reassigned, never left as it was. The stored copy belongs to the OLD
		// password, so keeping it here would make GET /files/{id}/sharekey hand out a key
		// that no longer opens the file. The replacement is stored on the same terms
		// whether it was typed or generated - see storage.EncryptSharePassword.
		file.EncryptedSharePassword = storage.EncryptSharePassword(newSharePassword)
		downloadPasswordToken.DeleteAllForFile(file.Id)
	} else if removePassword {
		file.PasswordHash = ""
		file.EncryptedSharePassword = nil
		downloadPasswordToken.DeleteAllForFile(file.Id)
	}

	if file.HotlinkId != "" && !storage.IsAbleHotlink(file) {
		database.DeleteHotlink(file.HotlinkId)
		file.HotlinkId = ""
	} else if file.HotlinkId == "" && storage.IsAbleHotlink(file) {
		storage.AddHotlink(&file)
	}

	database.SaveMetaData(file)
	logging.LogEdit(file, user)
	outputFileApiInfo(w, file)
}

// generateNewKey generates and saves a new API key
func generateNewKey(defaultPermissions bool, userId int, friendlyName, filerequstId string) models.ApiKey {
	if friendlyName == "" {
		friendlyName = "Unnamed key"
	}
	newKey := models.ApiKey{
		Id:              helper.GenerateRandomString(LengthApiKey),
		PublicId:        helper.GenerateRandomString(LengthPublicId),
		FriendlyName:    friendlyName,
		Permissions:     models.ApiPermDefault,
		IsSystemKey:     false,
		UserId:          userId,
		UploadRequestId: filerequstId,
	}
	if !defaultPermissions {
		newKey.Permissions = models.ApiPermNone
	}
	database.SaveApiKey(newKey)
	return newKey
}

func apiDeleteKey(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramAuthDelete)
	if !ok {
		panic("invalid parameter passed")
	}
	apiKeyOwner, apiKey, ok := isValidKeyForEditing(request.KeyId)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid key ID provided.")
		return
	}
	if apiKeyOwner.Id != user.Id && !user.HasPermission(models.UserPermManageApiKeys) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to delete this API key")
		return
	}
	// UserPermManageApiKeys is grantable to a plain user, so without this the super admin's own
	// key would be the one key such a user could still reach.
	if apiKeyOwner.Id != user.Id && apiKeyOwner.IsSuperAdmin() {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to delete this API key")
		return
	}
	database.DeleteApiKey(apiKey.Id)
	logging.LogApiKeyDeleted(apiKey, user)
}

func apiModifyApiKey(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramAuthModify)
	if !ok {
		panic("invalid parameter passed")
	}
	apimutex.Lock(apimutex.TypeApiKey, request.KeyId)
	defer apimutex.Unlock(apimutex.TypeApiKey, request.KeyId)

	apiKeyOwner, apiKey, ok := isValidKeyForEditing(request.KeyId)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid key ID provided.")
		return
	}
	if apiKeyOwner.Id != user.Id && !user.HasPermission(models.UserPermManageApiKeys) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to delete this API key")
		return
	}
	// UserPermManageApiKeys is grantable to a plain user, so without this the super admin's own
	// key would be the one key such a user could still reach.
	if apiKeyOwner.Id != user.Id && apiKeyOwner.IsSuperAdmin() {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to delete this API key")
		return
	}

	if request.IsPermissionSet {
		switch request.Permission {
		case models.ApiPermReplace:
			if !apiKeyOwner.HasPermissionReplace() {
				sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "Insufficient user permission for owner to set this API permission")
				return
			}
		case models.ApiPermManageUsers:
			if !apiKeyOwner.HasPermissionManageUsers() {
				sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "Insufficient user permission for owner to set this API permission")
				return
			}
		case models.ApiPermManageLogs:
			if !apiKeyOwner.HasPermissionManageLogs() {
				sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "Insufficient user permission for owner to set this API permission")
				return
			}
		case models.ApiPermManageFileRequests:
			if !apiKeyOwner.HasPermissionCreateFileRequests() {
				sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "Insufficient user permission for owner to set this API permission")
				return
			}
		default:
			// do nothing
		}
		if request.GrantPermission && !apiKey.HasPermission(request.Permission) {
			apiKey.GrantPermission(request.Permission)
			database.SaveApiKey(apiKey)
			logging.LogApiKeyPermissionChanged(apiKey, user, fmt.Sprintf("%d", request.Permission), true)
		} else if !request.GrantPermission && apiKey.HasPermission(request.Permission) {
			apiKey.RemovePermission(request.Permission)
			database.SaveApiKey(apiKey)
			logging.LogApiKeyPermissionChanged(apiKey, user, fmt.Sprintf("%d", request.Permission), false)
		}
	}

	if request.IsFriendlyNameSet {
		err := setApiKeyFriendlyName(apiKey.Id, request.FriendlyName)
		if err != nil {
			sendError(w, http.StatusInternalServerError, errorcodes.InternalServer, err.Error())
			return
		}
	}
}

// isValidKeyForEditing checks if the provided API key is either a public or private ID and returns the user and API
// key model (including the private ID)
func isValidKeyForEditing(apiKey string) (models.User, models.ApiKey, bool) {
	apiKey = publicKeyToApiKey(apiKey)
	user, fullApiKey, ok := isValidApiKey(apiKey, false, models.ApiPermNone)
	if !ok {
		return models.User{}, models.ApiKey{}, false
	}
	return user, fullApiKey, true
}

func isValidUserForEditing(w http.ResponseWriter, userId int) (models.User, bool) {
	user, ok := database.GetUser(userId)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid user id provided.")
		return models.User{}, false
	}
	return user, true
}

// canAdministerUser reports whether actor may mutate target's rank or permissions: never the
// super admin, never yourself, and actor must outrank target. UserRank is lower for a higher
// rank (super admin 0, admin 1, user 2), so outranking is a strict less-than - a rank-2 user
// holding UserPermManageUsers can therefore never administer another rank-2 user, let alone an
// admin, closing the gap where such a user could previously demote an admin or strip their
// permissions one bit at a time.
func canAdministerUser(actor, target models.User) bool {
	if target.IsSuperAdmin() {
		return false
	}
	if target.IsSameUser(actor.Id) {
		return false
	}
	return actor.UserLevel < target.UserLevel
}

func apiCreateApiKey(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramAuthCreate)
	if !ok {
		panic("invalid parameter passed")
	}

	if configuration.GetEnvironment().DisableApiMenu && !user.IsAdmin() {
		sendError(w, http.StatusForbidden, errorcodes.NoPermission, "User API keys are disabled for this instance")
		return
	}

	key := generateNewKey(request.BasicPermissions, user.Id, request.FriendlyName, "")
	logging.LogApiKeyCreated(key, user)
	output := models.ApiKeyOutput{
		Result:   "OK",
		Id:       key.Id,
		PublicId: key.PublicId,
	}
	result, err := json.Marshal(output)
	helper.Check(err)
	_, _ = w.Write(result)
}

// apiGetCurrentUser returns the calling user's information, plus whether apiGetUserAvatar has a
// cached picture to serve. HasAvatar lets the client skip that request entirely for the common
// case of an internal account, rather than making it on every page load only to be told 204.
func apiGetCurrentUser(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	_, hasAvatar := avatar.Path(user.Id)
	response := struct {
		models.User
		HasAvatar bool `json:"hasAvatar"`
	}{
		User:      user,
		HasAvatar: hasAvatar,
	}
	result, err := json.Marshal(response)
	helper.Check(err)
	_, _ = w.Write(result)
}

// apiGetUserAvatar serves the caller's own cached OIDC profile picture. The picture is always a
// PNG, because the avatar package re-encodes whatever the provider sent, and it is always served
// from this origin so the production CSP's img-src 'self' covers it.
func apiGetUserAvatar(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	path, ok := avatar.Path(user.Id)
	if !ok {
		// 204 rather than 404: "this account has no picture" is an ordinary answer for every
		// internal account and for any provider that sends no picture claim, so the client
		// should not have to tell it apart from a genuine error.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		sendError(w, http.StatusInternalServerError, errorcodes.InternalServer, "Could not read the profile picture")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(content)
}

func apiGetUserList(w http.ResponseWriter, _ requestParser, _ models.User, _ models.ApiKey) {
	type userListItem struct {
		Id            int    `json:"id"`
		Name          string `json:"name"`
		Permissions   int    `json:"permissions"`
		UserLevel     int    `json:"userLevel"`
		LastOnline    int64  `json:"lastOnline"`
		ResetPassword bool   `json:"resetPassword"`
		UploadCount   int    `json:"uploadCount"`
		AuthProvider  string `json:"authProvider"`
	}

	uploadCounts := storage.GetUploadCounts()
	var result []userListItem
	for _, userEntry := range database.GetAllUsers() {
		result = append(result, userListItem{
			Id:            userEntry.Id,
			Name:          userEntry.Name,
			Permissions:   int(userEntry.Permissions),
			UserLevel:     int(userEntry.UserLevel),
			LastOnline:    userEntry.LastOnline,
			ResetPassword: userEntry.ResetPassword,
			UploadCount:   uploadCounts[userEntry.Id],
			AuthProvider:  userEntry.AuthProvider,
		})
	}
	resultJson, err := json.Marshal(result)
	helper.Check(err)
	_, _ = w.Write(resultJson)
}

// apiGetUserDirectory lists every other account's id and name and nothing else, for the
// collaborator picker (models.FileRequest.Collaborators).
func apiGetUserDirectory(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	type directoryEntry struct {
		Id   int    `json:"id"`
		Name string `json:"name"`
	}
	result := make([]directoryEntry, 0)
	for _, entry := range database.GetAllUsers() {
		if entry.Id == user.Id {
			continue
		}
		result = append(result, directoryEntry{Id: entry.Id, Name: entry.Name})
	}
	resultJson, err := json.Marshal(result)
	helper.Check(err)
	_, _ = w.Write(resultJson)
}

func apiGetAuthList(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	type apiKeyListItem struct {
		Id              string `json:"id,omitempty"`
		PublicId        string `json:"publicId"`
		FriendlyName    string `json:"friendlyName"`
		Permissions     int    `json:"permissions"`
		LastUsed        int64  `json:"lastUsed"`
		Expiry          int64  `json:"expiry"`
		IsOwnedByCaller bool   `json:"isOwnedByCaller"`
		UserId          int    `json:"userId"`
	}

	// Build user map for existence check
	userMap := make(map[int]bool)
	for _, u := range database.GetAllUsers() {
		userMap[u.Id] = true
	}

	// Filter API keys
	var filteredKeys []models.ApiKey
	for _, apiKey := range database.GetAllApiKeys() {
		// Skip if user doesn't exist
		if !userMap[apiKey.UserId] {
			continue
		}
		// Skip system keys
		if apiKey.IsSystemKey {
			continue
		}
		// Skip file request keys
		if apiKey.IsUploadRequestKey() {
			continue
		}
		// Include only if owned by caller or caller can manage API keys
		if apiKey.UserId != user.Id && !user.HasPermission(models.UserPermManageApiKeys) {
			continue
		}
		filteredKeys = append(filteredKeys, apiKey)
	}

	// Sort by LastUsed desc, then by Id asc
	sort.Slice(filteredKeys, func(i, j int) bool {
		if filteredKeys[i].LastUsed != filteredKeys[j].LastUsed {
			return filteredKeys[i].LastUsed > filteredKeys[j].LastUsed
		}
		return filteredKeys[i].Id < filteredKeys[j].Id
	})

	var result []apiKeyListItem
	for _, apiKey := range filteredKeys {
		isOwned := apiKey.UserId == user.Id
		item := apiKeyListItem{
			Id:              apiKey.GetRedactedId(),
			PublicId:        apiKey.PublicId,
			FriendlyName:    apiKey.FriendlyName,
			Permissions:     int(apiKey.Permissions),
			LastUsed:        apiKey.LastUsed,
			Expiry:          apiKey.Expiry,
			IsOwnedByCaller: isOwned,
			UserId:          apiKey.UserId,
		}
		result = append(result, item)
	}
	resultJson, err := json.Marshal(result)
	helper.Check(err)
	_, _ = w.Write(resultJson)
}

func apiAuthInfo(w http.ResponseWriter, _ requestParser, _ models.User, _ models.ApiKey) {
	type authInfoResponse struct {
		Method            int    `json:"method"`
		PublicName        string `json:"publicName"`
		MinPasswordLength int    `json:"minPasswordLength"`
	}

	config := configuration.Get()
	env := configuration.GetEnvironment()
	result := authInfoResponse{
		Method:            config.Authentication.Method,
		PublicName:        config.PublicName,
		MinPasswordLength: env.MinLengthPassword,
	}
	resultJson, err := json.Marshal(result)
	helper.Check(err)
	_, _ = w.Write(resultJson)
}

// apiSealStatus reports whether the instance's master encryption key is currently loaded into
// memory (see encryption.IsSealed). Unauthenticated like /auth/info above: the SPA needs this to
// decide whether to show an unseal prompt before an admin can even log in, in the general case.
// Deliberately does NOT report the configured encryption level: that has no legitimate use for an
// unauthenticated caller and only helps an attacker fingerprint the instance (e.g. confirming
// Level 4 - full server-side encryption with an anonymously reachable /api/unseal - is worth
// attacking). An authenticated caller that needs the level already has /api/config/info or the
// admin API for that.
func apiSealStatus(w http.ResponseWriter, _ requestParser, _ models.User, _ models.ApiKey) {
	type sealStatusResponse struct {
		Sealed bool `json:"sealed"`
	}
	result, err := json.Marshal(sealStatusResponse{
		Sealed: encryption.IsSealed(),
	})
	helper.Check(err)
	_, _ = w.Write(result)
}

// isHostLocalUnsealRequest reports whether the request reached the server directly, without passing
// through the reverse proxy in front of it. It deliberately does NOT use logging.GetIpAddress /
// GOKAPI_TRUSTED_PROXIES: it inspects the raw transport peer and the raw presence of forwarding
// headers, so it cannot be spoofed by a client-supplied X-Forwarded-For. Caddy and ingress-nginx
// both always append X-Forwarded-For, so the presence of either forwarding header is enough to
// reject a proxied request; a caller reaching the app directly (on the VM, or through an SSH tunnel
// to the loopback-published port) sends neither.
//
// The peer is required to be loopback or a private address rather than loopback alone: the app runs
// in a container whose port is published on 127.0.0.1 only, and Docker's userland proxy rewrites
// the source to the bridge gateway (a private address), so an on-host caller never actually presents
// a loopback peer to the app. The real security boundary is that the port is not reachable off-host
// AND every proxied path adds a forwarding header, so a request with neither a forwarding header nor
// a public peer must have originated on the host itself. Used to fence off the master-key unseal
// endpoint from the public internet.
func isHostLocalUnsealRequest(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// apiUnseal is the sole way to load the master key at runtime for the Input encryption levels
// (LocalEncryptionInput/FullEncryptionInput) - see encryption.Unseal. It is restricted to a
// host-local, unproxied connection (see isHostLocalUnsealRequest): the master-key passphrase is far
// too sensitive to accept from the public internet, so this endpoint is reachable only from the host
// itself - on the VM directly, or through an SSH tunnel to 127.0.0.1:<port>. Any request that
// traversed the reverse proxy chain (ingress-nginx -> Caddy -> 127.0.0.1) carries an
// X-Forwarded-For header and is answered with a plain 404, so the endpoint is not even
// discoverable from the outside. This gate is checked FIRST, before the rate limiter, the seal
// check, and any body parsing. No session/API key can be required here because in the general case
// none can exist before the key is loaded; the loopback restriction is the authentication.
//
// Rate limited per IP (see ratelimiter.AllowUnseal): once an IP exceeds its burst
// it gets an immediate 429, checked BEFORE anything else in this function - including the cheap
// encryption.IsSealed() check below and, further down, the scrypt-driven encryption.Unseal call -
// so a flood from a single source is turned away before it can occupy the single derivation slot
// (see unsealSemaphore) or do any other work at all. encryption.Unseal additionally enforces a
// process-wide cap of one derivation in flight at a time (see ErrUnsealBusy); a second concurrent
// request also gets 429, without ever touching scrypt, which bounds memory to ~1 GiB regardless of
// attacker concurrency or how many IPs are used.
//
// If the instance is not currently sealed, this returns 409 immediately and does NOT call
// encryption.Unseal at all: encryption.Unseal returns nil (success) for an already-unsealed
// instance regardless of the password supplied - by design, so a retried request after a genuine
// unseal is a harmless no-op (see its doc comment) - which previously meant ANY caller, with ANY
// password (including none), could hit this endpoint on an already-unsealed instance and receive
// a 200 OK that was then audited as "unsealed successfully by IP x". That let an anonymous caller
// forge a successful-unseal audit trail entry at will. The check here closes that: no password is
// ever compared against anything on this path, so nothing is logged for it either - only an
// attempt that actually reaches the passphrase/checksum comparison inside encryption.Unseal is
// recorded via logging.LogUnsealAttempt, matching its own doc comment. Every attempt that does
// reach that comparison - successful or not - is written to the audit log; the 429 and 409 paths
// above are not password attempts, so they are not logged as one. The response never distinguishes
// "wrong password" from any other failure reason, so a caller learns nothing beyond
// correct/incorrect.
//
// Consecutive failed attempts from a single IP are counted separately (see
// ratelimiter.RecordUnsealFailure) purely to raise a high-severity alert once brute-forcing looks
// likely - never to lock the endpoint out, since an attacker could otherwise weaponise a lockout
// to deny the real admin their own recovery path.
func apiUnseal(w http.ResponseWriter, r *http.Request) {
	if !isHostLocalUnsealRequest(r) {
		http.NotFound(w, r)
		return
	}
	ip := logging.GetIpAddress(r)
	if !ratelimiter.AllowUnseal(ip) {
		sendError(w, http.StatusTooManyRequests, errorcodes.RateLimited, "Too many unseal attempts. Please wait before retrying")
		return
	}
	if !encryption.IsSealed() {
		sendError(w, http.StatusConflict, errorcodes.AlreadyExists, "Instance is not sealed")
		return
	}

	const maxBodySize = 4 * 1024
	bodyReader := http.MaxBytesReader(w, r.Body, maxBodySize)
	var input struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(bodyReader).Decode(&input); err != nil {
		sendError(w, http.StatusBadRequest, errorcodes.CannotParse, "Invalid request body")
		return
	}

	err := encryption.Unseal(input.Password)
	if err != nil {
		if errors.Is(err, encryption.ErrUnsealBusy) {
			sendError(w, http.StatusTooManyRequests, errorcodes.RateLimited, "Too many unseal attempts. Please wait before retrying")
			return
		}
		logging.LogUnsealAttempt(ip, false)
		ratelimiter.RecordUnsealFailure(ip)
		sendError(w, http.StatusUnauthorized, errorcodes.InstanceSealed, "Incorrect password")
		return
	}
	logging.LogUnsealAttempt(ip, true)
	ratelimiter.RecordUnsealSuccess(ip)
	// The master key only exists from here on, so this is the first moment an instance running at
	// an Input encryption level can encrypt the file names an older version stored in plaintext.
	storage.MigratePlaintextFileNames()
	_, _ = io.WriteString(w, `{"Result":"OK"}`)
}

func apiCreateUser(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramUserCreate)
	if !ok {
		panic("invalid parameter passed")
	}
	newUser, err := users.Create(request.Username, request.AuthProvider, "")
	if err != nil {
		switch {
		case errors.Is(err, users.ErrorNameToShort):
			sendError(w, http.StatusBadRequest, errorcodes.NoPermission, "Invalid username provided.")
		case errors.Is(err, users.ErrorUserExists):
			sendError(w, http.StatusConflict, errorcodes.AlreadyExists, "User already exists.")
		default:
			sendError(w, http.StatusInternalServerError, errorcodes.InternalServer, err.Error())
		}
		return
	}
	logging.LogUserCreation(newUser, user)
	_, _ = w.Write([]byte(newUser.ToJson()))
}

// setApiKeyFriendlyName renames the key. Callers must already hold apimutex.TypeApiKey for id -
// apiModifyApiKey does, for the whole request, since a rename may be combined with a permission
// change on the same key in one call.
func setApiKeyFriendlyName(id string, newName string) error {
	if newName == "" {
		newName = "Unnamed key"
	}

	key, ok := database.GetApiKey(id)
	if !ok {
		return errors.New("could not modify API key")
	}
	if key.FriendlyName != newName {
		key.FriendlyName = newName
		database.SaveApiKey(key)
	}
	return nil
}

func apiDeleteFile(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesDelete)
	if !ok {
		panic("invalid parameter passed")
	}
	file, ok := database.GetMetaDataById(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid file ID provided.")
		return
	}
	if file.UserId != user.Id && !user.HasPermission(models.UserPermDeleteOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to delete this file")
		return
	}
	// Fail closed: commit the audit record before anything is deleted, mirroring the download
	// path in FileServing.go. If the write fails, refuse the deletion instead of removing the
	// file with no durable record of it.
	if err := logging.LogDelete(file, user); err != nil {
		fmt.Println("audit: refusing to delete, could not record audit event:", err)
		sendError(w, http.StatusServiceUnavailable, errorcodes.AuditWriteFailed, "Service temporarily unavailable, please try again.")
		return
	}
	if request.DelaySeconds == 0 {
		_ = storage.DeleteFile(request.Id, true)
	} else {
		_ = storage.DeleteFileSchedule(request.Id, request.DelaySeconds*1000, true)
	}
}

func apiRestoreFile(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesRestore)
	if !ok {
		panic("invalid parameter passed")
	}
	file, ok := database.GetMetaDataById(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid file ID provided or file has already been deleted.")
		return
	}
	if file.UserId != user.Id && !user.HasPermission(models.UserPermDeleteOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to restore this file")
		return
	}
	file, ok = storage.CancelPendingFileDeletion(file.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid file ID provided or file has already been deleted.")
		return
	}
	logging.LogRestore(file, user)
	outputFileJson(w, file)
}

func apiFolderCreate(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFolderCreate)
	if !ok {
		panic("invalid parameter passed")
	}

	// Cap folder name length at 256 characters
	if len(request.Name) > 256 {
		sendError(w, http.StatusBadRequest, errorcodes.CannotParse, "Folder name is too long (maximum 256 characters)")
		return
	}

	// filebundle.Create saves the bundle straight through to SaveFileBundle, which needs the
	// master key to encrypt the name (see encryptBundleNameForSave). Checked here rather than
	// left to fail inside it: an ErrSealed there would reach helper.Check and panic the request
	// instead of answering with a clean refusal, the same way ServeFile refuses a sealed instance.
	if encryption.IsSealed() {
		sendError(w, http.StatusServiceUnavailable, errorcodes.InstanceSealed, "Instance is sealed")
		return
	}

	// Validated and hashed up front, before the bundle is even created, so a rejected password
	// (too short, or whitespace that trims to nothing) never leaves a half-configured folder
	// behind - same reasoning as apiEditFile.
	var newPasswordHash string
	var newSharePassword string
	if request.IsPasswordSet {
		validatedPassword, err := configuration.ValidateSharePassword(request.Password, request.IsPasswordSet)
		if err != nil {
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
			return
		}
		newPasswordHash = configuration.HashPassword(validatedPassword, false, "")
		newSharePassword = validatedPassword
	}

	bundle := filebundle.Create(request.Name, user.Id)

	if request.IsPasswordSet {
		bundle.PasswordHash = newPasswordHash
		bundle.EncryptedSharePassword = storage.EncryptSharePassword(newSharePassword)
	}
	if request.UnlimitedDownloads {
		bundle.UnlimitedDownloads = true
	} else if request.AllowedDownloads != 0 {
		bundle.DownloadsRemaining = request.AllowedDownloads
		bundle.UnlimitedDownloads = false
	}
	if request.UnlimitedExpiry {
		bundle.UnlimitedTime = true
	} else if request.ExpiryTimestamp != 0 {
		bundle.ExpireAt = request.ExpiryTimestamp
		bundle.UnlimitedTime = false
	}
	// Creation paths are clamped to the retention cap the same way file uploads are - see
	// fileupload.CreateUploadConfig.
	bundle.ExpireAt, bundle.UnlimitedTime = fileupload.ClampExpiryTimestamp(bundle.ExpireAt, bundle.UnlimitedTime)
	database.SaveFileBundle(bundle)

	logging.LogFolderCreate(bundle, user)

	type FolderCreateResponse struct {
		Result     string            `json:"Result"`
		FileBundle models.FileBundle `json:"FileBundle"`
	}
	response := FolderCreateResponse{
		Result:     "OK",
		FileBundle: bundle,
	}
	result, err := json.Marshal(response)
	helper.Check(err)
	_, _ = w.Write(result)
}

func apiFolderList(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	allBundles := filebundle.GetAll()
	allFiles := database.GetAllMetadata()

	type BundleWithMetadata struct {
		models.FileBundle
		MemberCount    int   `json:"membercount"`
		TotalSizeBytes int64 `json:"totalsizebytes"`
	}

	result := make([]BundleWithMetadata, 0)
	for _, bundle := range allBundles {
		if bundle.UserId == user.Id || user.HasPermission(models.UserPermListOtherUploads) {
			// Listing view, not serving view: a disposed member keeps its row and its size in
			// the file list, so the folder above it must count the same rows. See
			// models.FileBundle.RetainedTotals.
			totalSize, memberCount := bundle.RetainedTotals(allFiles)
			// bundle.Name is empty when it could not be decrypted (see models.FileBundle.Name),
			// which happens while the instance is sealed. Rendered as the placeholder rather than
			// left blank; the underlying bundle is left untouched, only this local copy going to
			// JSON is changed.
			bundle.Name = bundle.DisplayName()
			result = append(result, BundleWithMetadata{
				FileBundle:     bundle,
				MemberCount:    memberCount,
				TotalSizeBytes: totalSize,
			})
		}
	}

	jsonResult, err := json.Marshal(result)
	helper.Check(err)
	_, _ = w.Write(jsonResult)
}

func apiFolderDelete(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFolderDelete)
	if !ok {
		panic("invalid parameter passed")
	}

	bundle, ok := filebundle.Get(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Folder does not exist")
		return
	}

	if bundle.UserId != user.Id && !user.HasPermission(models.UserPermDeleteOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to delete this folder")
		return
	}

	// Fail closed: commit a single batched audit record covering every member file and the
	// folder itself before anything is deleted. This used to be N+1 separate synchronous
	// fsyncs (one appendAuditEntry call per member plus one for the folder), each taking the
	// package-global audit mutex - for a folder with thousands of members that could exceed the
	// write timeout and stalled every concurrent download that also needed an audit write, since
	// they share the same mutex. LogFolderDeleteBatch takes the mutex and fsyncs exactly once
	// for the whole folder, and writes nothing at all if any part of the batch fails, so an
	// aborted delete never leaves a durable "deleted" record for a member that was never
	// actually deleted.
	memberFiles := filebundle.GetFiles(bundle)
	if err := logging.LogFolderDeleteBatch(bundle, memberFiles, user); err != nil {
		fmt.Println("audit: refusing to delete folder, could not record audit event:", err)
		sendError(w, http.StatusServiceUnavailable, errorcodes.AuditWriteFailed, "Service temporarily unavailable, please try again.")
		return
	}

	filebundle.Delete(bundle)

	type FolderDeleteResponse struct {
		Result string `json:"Result"`
	}
	response := FolderDeleteResponse{
		Result: "OK",
	}
	jsonResult, err := json.Marshal(response)
	helper.Check(err)
	_, _ = w.Write(jsonResult)
}

func apiFolderModify(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFolderModify)
	if !ok {
		panic("invalid parameter passed")
	}
	// Serialised the same way apiEditFile serialises an edit of a single file, so two concurrent
	// edits of one folder cannot each save a full bundle read before the other's write. The key is
	// a bundle ID rather than a file ID, which at worst shares a stripe with an unrelated file.
	apimutex.Lock(apimutex.TypeMetaData, request.Id)
	defer apimutex.Unlock(apimutex.TypeMetaData, request.Id)

	bundle, ok := filebundle.Get(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Folder does not exist")
		return
	}

	if bundle.UserId != user.Id && !user.HasPermission(models.UserPermEditOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to edit this folder")
		return
	}

	// database.SaveFileBundle needs the master key to encrypt the name (see
	// encryptBundleNameForSave), and a new password has to be encrypted for the share key as
	// well. Checked here for the same reason apiFolderCreate checks it: an ErrSealed deeper down
	// would reach helper.Check and panic the request instead of answering with a clean refusal.
	if encryption.IsSealed() {
		sendError(w, http.StatusServiceUnavailable, errorcodes.InstanceSealed, "Instance is sealed")
		return
	}

	// Validated up front, before any field of bundle is touched, so that a rejected name or
	// password leaves every other requested edit unsaved too, instead of applying a partial
	// update - same reasoning as apiEditFile.
	if request.IsNameSet && request.Name == "" {
		sendError(w, http.StatusBadRequest, errorcodes.CannotParse, "Folder name must not be empty")
		return
	}
	// Cap folder name length at 256 characters
	if len(request.Name) > 256 {
		sendError(w, http.StatusBadRequest, errorcodes.CannotParse, "Folder name is too long (maximum 256 characters)")
		return
	}

	// changePassword is true only when the caller actually sent a "password" header, and removal
	// is its own explicit signal - see paramFilesModify.ProcessParameter, whose semantics
	// paramFolderModify copies exactly.
	changePassword := request.IsPasswordSet
	removePassword := request.RemovePassword
	var newPasswordHash string
	var newSharePassword string
	if changePassword {
		validatedPassword, err := configuration.ValidateSharePassword(request.Password, request.IsPasswordSet)
		if err != nil {
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
			return
		}
		newPasswordHash = configuration.HashPassword(validatedPassword, false, "")
		newSharePassword = validatedPassword
	}

	if request.IsNameSet {
		bundle.Name = request.Name
	}
	if request.UnlimitedDownloads {
		bundle.UnlimitedDownloads = true
	} else {
		if request.AllowedDownloads != 0 {
			bundle.DownloadsRemaining = request.AllowedDownloads
			bundle.UnlimitedDownloads = false
		}
	}
	if request.UnlimitedExpiry {
		bundle.UnlimitedTime = true
	} else {
		if request.ExpiryTimestamp != 0 {
			bundle.ExpireAt = request.ExpiryTimestamp
			bundle.UnlimitedTime = false
		}
	}
	// Creation is clamped in apiFolderCreate, but this one writes the expiry directly, so the
	// retention cap has to be applied here too. Clamping after the branches above also catches a
	// folder that predates the cap being configured. Same as apiEditFile.
	bundle.ExpireAt, bundle.UnlimitedTime = fileupload.ClampExpiryTimestamp(bundle.ExpireAt, bundle.UnlimitedTime)

	if changePassword {
		bundle.PasswordHash = newPasswordHash
		// Always reassigned, never left as it was. The stored copy belongs to the OLD password,
		// so keeping it here would make GET /folder/{id}/sharekey hand out a key that no longer
		// opens the folder. Stored on the same terms whether it was typed or generated - see
		// storage.EncryptSharePassword.
		bundle.EncryptedSharePassword = storage.EncryptSharePassword(newSharePassword)
		// A folder password cookie is registered under "bundle:"+id, not the bare id - see
		// writeFolderPwCookie in Webserver.go. Without this, whoever entered the old password
		// keeps the folder open for the remaining lifetime of their cookie after the owner
		// rotated it.
		downloadPasswordToken.DeleteAllForFile("bundle:" + bundle.Id)
	} else if removePassword {
		bundle.PasswordHash = ""
		bundle.EncryptedSharePassword = nil
		downloadPasswordToken.DeleteAllForFile("bundle:" + bundle.Id)
	}

	database.SaveFileBundle(bundle)

	logging.LogFolderEdit(bundle, user)

	type FolderModifyResponse struct {
		Result     string            `json:"Result"`
		FileBundle models.FileBundle `json:"FileBundle"`
	}
	response := FolderModifyResponse{
		Result:     "OK",
		FileBundle: bundle,
	}
	result, err := json.Marshal(response)
	helper.Check(err)
	_, _ = w.Write(result)
}

func apiChunkAdd(w http.ResponseWriter, r requestParser, _ models.User, _ models.ApiKey) {
	request, ok := r.(*paramChunkAdd)
	if !ok {
		panic("invalid parameter passed")
	}
	statusCode, errCode, errString := processNewChunk(w, request, configuration.Get().MaxFileSizeMB, "")
	if statusCode != http.StatusOK {
		sendError(w, statusCode, errCode, errString)
	}
}

func apiChunkReserve(w http.ResponseWriter, r requestParser, _ models.User, apikey models.ApiKey) {
	request, ok := r.(*paramChunkReserve)
	if !ok {
		panic("invalid parameter passed")
	}
	fileRequest, ok, status, errorCode, errorMsg := checkFileRequestAndApiKey(w, request.WebRequest, request.Id, apikey)
	if !ok {
		sendError(w, status, errorCode, errorMsg)
		return
	}
	if !ratelimiter.WaitForNewUuid(fileRequest.Id) {
		sendError(w, http.StatusTooManyRequests, errorcodes.RateLimited, "Too many reservations for this file request. Please wait a few seconds before reserving a new uuid.")
		return
	}
	limit := -1
	if !fileRequest.IsUnlimitedFiles() {
		// Reservations count against the cap before they turn into an uploaded file (see
		// chunkreservation.SetUploading), so the budget for new reservations is the cap minus
		// what has already been uploaded - not FilesRemaining, which also subtracts the
		// reservation count NewIfUnder is about to recount atomically itself.
		limit = fileRequest.MaxFiles - fileRequest.UploadedFiles
	}
	uuid, ok := chunkreservation.NewIfUnder(fileRequest.Id, limit)
	if !ok {
		sendError(w, http.StatusBadRequest, errorcodes.CannotUploadMoreFiles, "No more files can be uploaded for this file request")
		return
	}
	result, err := json.Marshal(struct {
		Result string `json:"Result"`
		Uuid   string `json:"Uuid"`
	}{"OK", uuid})
	helper.Check(err)
	_, _ = w.Write(result)
}

func apiChunkUnreserve(w http.ResponseWriter, r requestParser, _ models.User, apikey models.ApiKey) {
	request, ok := r.(*paramChunkUnreserve)
	if !ok {
		panic("invalid parameter passed")
	}
	fileRequest, ok, status, errorCode, errorMsg := checkFileRequestAndApiKey(w, request.WebRequest, request.Id, apikey)
	if !ok {
		sendError(w, status, errorCode, errorMsg)
		return
	}
	chunkreservation.SetComplete(fileRequest.Id, request.Uuid)
	_ = chunking.DeleteChunk(request.Uuid)
	_, _ = w.Write([]byte(`{"Result":"OK"}`))
}

func apiChunkUploadRequestAdd(w http.ResponseWriter, r requestParser, user models.User, apikey models.ApiKey) {
	request, ok := r.(*paramChunkUploadRequestAdd)
	if !ok {
		panic("invalid parameter passed")
	}
	fileRequest, ok, status, errorCode, errorMsg := checkFileRequestAndApiKey(w, request.GetRequest(), request.FileRequestId, apikey)
	if !ok {
		sendError(w, status, errorCode, errorMsg)
		return
	}
	maxUpload := configuration.Get().MaxFileSizeMB
	if !user.IsAdmin() && configuration.GetEnvironment().MaxSizeGuestUploadMb != 0 {
		maxUpload = min(maxUpload, configuration.GetEnvironment().MaxSizeGuestUploadMb)
	}
	if !fileRequest.IsUnlimitedSize() {
		maxUpload = min(maxUpload, fileRequest.MaxSize)
	}
	statusCode, errorCode, errString := processNewChunk(w, request, maxUpload, fileRequest.Id)
	if statusCode != http.StatusOK {
		sendError(w, statusCode, errorCode, errString)
	}
}

func checkFileRequestAndApiKey(w http.ResponseWriter, r *http.Request, fileRequestId string, apiKey models.ApiKey) (models.FileRequest, bool, int, int, string) {
	fileRequest, ok := filerequest.Get(fileRequestId)
	if !ok {
		return models.FileRequest{}, false, http.StatusNotFound, errorcodes.NotFound, "FileRequest does not exist with the given ID"
	}
	if fileRequest.ApiKey != apiKey.Id {
		return models.FileRequest{}, false, http.StatusUnauthorized, errorcodes.InvalidApiKey, "Invalid API key"
	}
	// A request mailed to named recipients is not authorised by its api key alone. The entry
	// endpoint (pubApiUploadRequest) refuses a non-recipient, but it hands the api key to
	// everyone it lets past, and that key keeps working after the holder is removed from the
	// list - so the same question has to be asked again on every chunk, or removing a recipient
	// revokes their downloads immediately and their uploads never. shareaccess.RecipientFor is
	// the same resolution the download paths use: a sharetoken header, a ?token= query fallback,
	// then a cookie, with the grant re-checked against the database every time.
	//
	// An unrestricted request has no recipient list to be on and is untouched: a public upload
	// link keeps working for anonymous guests holding the api key.
	if database.IsShareRestricted(models.ShareResourceFileRequest, fileRequestId) {
		if shareaccess.RecipientFor(w, r, models.ShareResourceFileRequest, fileRequestId) == 0 {
			// Refused as "not found", the same convention a restricted bundle gets in
			// pubApiFolder, so this answer says no more than the not-found branch above does.
			// The caller is told what is actually wrong by the entry endpoint, which reports
			// valid:false/identity when they reload the upload page.
			return models.FileRequest{}, false, http.StatusNotFound, errorcodes.NotFound, "FileRequest does not exist with the given ID"
		}
	}
	if !fileRequest.IsUnlimitedTime() && fileRequest.Expiry < time.Now().Unix() {
		return models.FileRequest{}, false, http.StatusUnauthorized, errorcodes.RequestExpired, "Filerequest has expired"
	}
	if fileRequest.Closed {
		return models.FileRequest{}, false, http.StatusUnauthorized, errorcodes.RequestClosed, "Filerequest has been marked complete"
	}
	if !fileRequest.IsUnlimitedFiles() && fileRequest.UploadedFiles >= fileRequest.MaxFiles {
		return models.FileRequest{}, false, http.StatusUnauthorized, errorcodes.CannotUploadMoreFiles, "Max file count has already been reached for this file request"
	}
	return fileRequest, true, 0, 0, ""
}

type chunkParams interface {
	GetRequest() *http.Request
}

func processNewChunk(w http.ResponseWriter, request chunkParams, maxFileSizeMb int, filerequestId string) (int, int, string) {
	maxUpload := int64(maxFileSizeMb) * 1024 * 1024
	if request.GetRequest().ContentLength > maxUpload {
		return http.StatusBadRequest, errorcodes.FileTooLarge, storage.ErrorFileTooLarge.Error()
	}
	request.GetRequest().Body = http.MaxBytesReader(w, request.GetRequest().Body, maxUpload)
	errCode, err := fileupload.ProcessNewChunk(w, request.GetRequest(), true, filerequestId, maxUpload)
	if err != nil {
		return http.StatusBadRequest, errCode, err.Error()
	}
	return http.StatusOK, 0, ""
}

func apiChunkComplete(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramChunkComplete)
	if !ok {
		panic("invalid parameter passed")
	}
	if request.BundleId != "" {
		bundle, exists := database.GetFileBundle(request.BundleId)
		// A deleted folder keeps its row for as long as its disposed members keep theirs (see
		// models.FileBundle.DeletedAt), and it answers here exactly as a folder that never existed
		// does. Uploading into one would give a folder nobody can open a member that is not
		// disposed of, which is the one thing that would keep its row alive indefinitely.
		if !exists || bundle.DeletedAt != 0 {
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, "bundle not found")
			return
		}
		if bundle.UserId != user.Id {
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, "bundle does not belong to user")
			return
		}
	}
	validatedPassword, err := configuration.ValidateSharePassword(request.Password, request.foundHeaders["password"])
	if err != nil {
		sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
		return
	}
	uploadParams, err := fileupload.CreateUploadConfig(request.AllowedDownloads,
		request.ExpiryDays,
		request.ExpiryTimestamp,
		validatedPassword,
		request.UnlimitedTime,
		request.UnlimitedDownloads,
		request.IsE2E,
		request.FileSize,
		"",
		request.BundleId,
		request.GeneratedPassword)
	if err != nil {
		sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
		return
	}
	if request.IsNonBlocking {
		// The client is told "OK" here, before the file is even created - see the doc comment
		// on doBlockingPartCompleteChunk for why the audit fail-closed guarantee does not cover
		// this branch.
		go doBlockingPartCompleteChunk(nil, request.WebRequest, request.Uuid, request.FileHeader, user, uploadParams, request.RecipientEmails)
		_, _ = io.WriteString(w, "{\"result\":\"OK\"}")
		return
	}
	doBlockingPartCompleteChunk(w, request.WebRequest, request.Uuid, request.FileHeader, user, uploadParams, request.RecipientEmails)
}

// doBlockingPartCompleteChunk finalises an uploaded chunked file and is the choke point for the
// LogUpload fail-closed guarantee - EXCEPT when it is invoked from the IsNonBlocking branch of
// apiChunkComplete/apiChunkUploadRequestComplete (both call it via `go doBlockingPartCompleteChunk(nil, ...)`).
// In that mode the client is already told "OK" before this function even runs, since the whole
// point of "non-blocking" is that CompleteChunk (which creates the file) and this function's
// audit write both happen after the response was sent. The rollback below still runs and still
// prevents an unaudited file from being left on disk, but the "never confirm an unaudited
// upload" guarantee does not hold for that path: the client has already been told the upload
// was accepted before the file, let alone its audit record, exists. Closing that gap would need
// a callback/polling completion signal, which is out of scope for this item.
//
// recipientEmails is only ever non-empty from apiChunkComplete (the authenticated upload path):
// apiChunkUploadRequestComplete, the guest/file-request completion path, always passes nil - a
// file request's own recipient list is managed separately, by editing the request itself, not by
// a guest uploading into it.
func doBlockingPartCompleteChunk(w http.ResponseWriter, r *http.Request, uuid string, fileHeader chunking.FileHeader, user models.User, uploadParameters models.UploadParameters, recipientEmails []string) {
	file, err := fileupload.CompleteChunk(uuid, fileHeader, user.Id, uploadParameters)
	if err != nil {
		_ = chunking.DeleteChunk(uuid)
		if errors.Is(err, storage.ErrorInstanceSealed) {
			sendError(w, http.StatusServiceUnavailable, errorcodes.InstanceSealed, err.Error())
			return
		}
		sendError(w, http.StatusBadRequest, errorcodes.UnspecifiedError, err.Error())
		return
	}
	if uploadParameters.FileRequestId != "" {
		chunkreservation.SetComplete(uploadParameters.FileRequestId, uuid)
	}
	fr, _ := filerequest.Get(uploadParameters.FileRequestId)
	if fr.Id != "" {
		// A restricted request's public upload page already exchanged the mailed token for a
		// cookie before the guest ever reached the chunk-complete call (pubApiUploadRequest ->
		// recipientFor). Reading it back here attributes the upload to the person who actually
		// uploaded it rather than to fr's owner, who moves into LogUpload's Detail instead. An
		// unrestricted request has no such cookie, so this is a no-op and behaviour is unchanged.
		if recipientId, ok := shareaccess.ReadCookie(r, models.ShareResourceFileRequest, fr.Id); ok {
			if recipient, ok := database.GetShareRecipient(recipientId); ok {
				r = logging.WithRecipient(r, recipient)
			}
		}
	}
	err = logging.LogUpload(file, user, fr, r, configuration.Get().SaveIp)
	if err != nil {
		// Fail closed: without a durable audit record of this upload, the file must not be
		// confirmed. Remove what was just stored rather than leave an unaudited file behind.
		deleteUnreachableUpload(file.Id, "an audit write failure")
		sendError(w, http.StatusServiceUnavailable, errorcodes.UnspecifiedError, "could not record audit event, upload refused")
		return
	}
	if fr.Id != "" && !fr.Closed && !fr.IsUnlimitedFiles() && fr.UploadedFiles >= fr.MaxFiles {
		closeFullFileRequest(fr, user)
	}

	storeBundleShareKey(file)

	if len(recipientEmails) > 0 {
		// Fail closed, per the 2026-09-02 audit decision: a recipient-only share must never
		// have a window where the file exists with no password and no grants. Creating the
		// grants is made part of this same request rather than left to a second call the SPA
		// used to make afterwards, which could fail on its own (mail down) or never happen at
		// all (browser closed before it fired) while leaving a fully public file behind.
		results, ok := grantUploadRecipients(w, file, user, recipientEmails)
		if !ok {
			return
		}
		outputFileJsonWithRecipients(w, file, results)
		return
	}
	outputFileJson(w, file)
}

// deleteUnreachableUpload removes a just-created file so that nothing it left behind is
// reachable, used by doBlockingPartCompleteChunk's fail-closed rollback paths: a missing audit
// record, or - now - a requested recipient restriction that could not be created. reason is
// logged only, never returned to the client.
func deleteUnreachableUpload(fileId, reason string) {
	if !storage.DeleteFile(fileId, true) {
		fmt.Println("audit: could not roll back upload", fileId, "after "+reason+
			" - the file may still be present on disk without the guarantee that required removing it")
	}
}

// storeBundleShareKey mirrors a freshly uploaded bundle member's stored share key (see
// storage.EncryptSharePassword) onto the member's bundle, the same way file's own
// EncryptedSharePassword is already populated by createNewMetaData. Folder creation
// (apiFolderCreate) has no password of its own - a folder's password protection is derived
// entirely from its members (see isValidFolderPassword) - so upload-complete, where a member's
// encrypted password is first computed, is the only point that ever has one to store. This
// mirrors where bundle recipient grants attach (see grantUploadRecipients' doc comment): both
// are properties of the bundle that only exist once a member upload supplies them.
//
// A no-op unless file belongs to a bundle, the upload actually produced a stored key (StoreShareKeys
// off, no password, or no master key all leave file.EncryptedSharePassword nil - see
// storage.EncryptSharePassword), and the bundle does not already have one stored. That last check,
// like grantUploadRecipients' "skip once already restricted", keeps every member after the first
// from re-writing the bundle row - the SPA applies one password to every member of a folder upload,
// so whichever member completes first is the one that establishes it.
func storeBundleShareKey(file models.File) {
	if file.BundleId == "" || len(file.EncryptedSharePassword) == 0 {
		return
	}
	bundle, ok := database.GetFileBundle(file.BundleId)
	if !ok || len(bundle.EncryptedSharePassword) > 0 {
		return
	}
	bundle.EncryptedSharePassword = file.EncryptedSharePassword
	database.SaveFileBundle(bundle)
}

// grantUploadRecipients makes a freshly uploaded file's recipient restriction part of the same
// atomic operation as the upload itself. If it cannot create the grants, it deletes the file
// that was just created and sends the error response, so the caller only needs to check ok and
// return - deleting rather than merely leaving the file unconfirmed matches the choice Ming made
// for this item: a `ShareRestricted` fail-closed column was rejected specifically because it
// would leave unreachable files behind, and creating the file first, then deleting it on failure,
// is the one mechanism doBlockingPartCompleteChunk already has (see the LogUpload failure branch
// above) for guaranteeing nothing is left reachable - inventing a second one (e.g. reserving the
// grants before the file exists) would need the file's own ID before CompleteChunk has assigned
// one, for no behavioural difference to the caller.
//
// A member of a bundle is restricted at the bundle, not at itself: FileServing gates a bundle
// member on the bundle's own restriction (see database.IsShareRestricted(ShareResourceBundle, ...)
// in Webserver.go), matching how the SPA has always applied one grant to the whole folder rather
// than to each file in it. Skipping the call once the bundle is already restricted keeps a
// multi-file folder upload from re-granting - and so re-mailing every recipient and revoking
// their still-live link - once per member file; the SPA sends the same recipient list with every
// member's completion for exactly this reason, so that whichever member happens to complete first
// is the one that establishes the restriction, and every member is refused until it does.
func grantUploadRecipients(w http.ResponseWriter, file models.File, user models.User, emails []string) ([]shareaccess.GrantResult, bool) {
	resource := shareaccess.Resource{
		Type: models.ShareResourceFile,
		Id:   file.Id,
		Name: file.Name,
		// ExpiresAt is left at the file's own expiry for a plain file. A bundle member below
		// overrides this to the bundle's own resource, which - matching resolveShareResource's
		// ShareResourceBundle case - leaves ExpiresAt at zero (capped at the access link's own
		// maximum) rather than trying to derive one from the bundle.
		ExpiresAt: shareExpiry(file.UnlimitedTime, file.ExpireAt),
	}

	if file.BundleId != "" {
		bundle, found := database.GetFileBundle(file.BundleId)
		if !found {
			deleteUnreachableUpload(file.Id, "its bundle disappeared before recipient grants could be created")
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, "bundle not found")
			return nil, false
		}
		resource = shareaccess.Resource{Type: models.ShareResourceBundle, Id: bundle.Id, Name: bundle.DisplayName()}
		if database.IsShareRestricted(resource.Type, resource.Id) {
			return nil, true
		}
	}

	results, err := shareaccess.GrantAccess(resource, emails, user, 0, configuration.Get().ServerUrl)
	if err != nil {
		deleteUnreachableUpload(file.Id, "its requested recipient grants could not be created: "+err.Error())
		if errors.Is(err, shareaccess.ErrMailNotConfigured) {
			sendError(w, http.StatusPreconditionFailed, errorcodes.NoPermission, err.Error())
		} else {
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
		}
		return nil, false
	}
	return results, true
}

// chunkCompleteRecipientOutput mirrors apiSetShareRecipients' recipientOutput: same fields, same
// json tags, so the SPA's ShareRecipientResult type covers both responses without a variant.
type chunkCompleteRecipientOutput struct {
	Email          string `json:"email"`
	IsNewRecipient bool   `json:"isNewRecipient"`
	MailError      string `json:"mailError,omitempty"`
}

// outputFileJsonWithRecipients is outputFileJson plus a "recipients" field reporting what
// grantUploadRecipients did. Only called when the request actually asked for a recipient
// restriction, so a plain upload's response is untouched (still exactly outputFileJson's shape) -
// this is the regression risk the "no recipients" tests guard.
func outputFileJsonWithRecipients(w http.ResponseWriter, file models.File, results []shareaccess.GrantResult) {
	if w == nil {
		return
	}
	config := configuration.Get()
	info, err := file.ToFileApiOutput(config.ServerUrl, config.IncludeFilename, storage.DownloadAccessOf(file))
	helper.Check(err)

	output := make([]chunkCompleteRecipientOutput, 0, len(results))
	for _, result := range results {
		entry := chunkCompleteRecipientOutput{Email: result.Email, IsNewRecipient: result.IsNewRecipient}
		if result.MailErr != nil {
			// The grant was still created, so the uploader can resend rather than rebuild the
			// share - see GrantResult.MailErr. Surfacing it here, on the upload response itself,
			// is what makes this visible even though it is not fatal to the upload: a toast alone
			// could be missed, or never seen if the tab is closed right after upload.
			entry.MailError = result.MailErr.Error()
		}
		output = append(output, entry)
	}

	type chunkCompleteResult struct {
		Result          string                         `json:"Result"`
		FileInfo        models.FileApiOutput           `json:"FileInfo"`
		IncludeFilename bool                           `json:"IncludeFilename"`
		Recipients      []chunkCompleteRecipientOutput `json:"recipients"`
	}
	output2, err := json.Marshal(chunkCompleteResult{
		Result:          "OK",
		FileInfo:        info,
		IncludeFilename: config.IncludeFilename,
		Recipients:      output,
	})
	helper.Check(err)
	_, _ = w.Write(output2)
}

func apiChunkUploadRequestComplete(w http.ResponseWriter, r requestParser, user models.User, apikey models.ApiKey) {
	request, ok := r.(*paramChunkUploadRequestComplete)
	if !ok {
		panic("invalid parameter passed")
	}
	fileRequest, ok, status, errorCode, errorMsg := checkFileRequestAndApiKey(w, request.WebRequest, request.FileRequestId, apikey)
	if !ok {
		sendError(w, status, errorCode, errorMsg)
		return
	}
	uploadParams, err := fileupload.CreateUploadConfig(0,
		0, 0, "", true, true,
		false, request.FileSize, fileRequest.Id, "", false)
	if err != nil {
		sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
		return
	}
	if request.IsNonBlocking {
		// The client is told "OK" here, before the file is even created - see the doc comment
		// on doBlockingPartCompleteChunk for why the audit fail-closed guarantee does not cover
		// this branch.
		go doBlockingPartCompleteChunk(nil, request.WebRequest, request.Uuid, request.FileHeader, user, uploadParams, nil)
		_, _ = io.WriteString(w, "{\"result\":\"OK\"}")
		return
	}
	doBlockingPartCompleteChunk(w, request.WebRequest, request.Uuid, request.FileHeader, user, uploadParams, nil)
}

func apiVersionInfo(w http.ResponseWriter, _ requestParser, _ models.User, _ models.ApiKey) {
	type versionInfo struct {
		Version    string
		VersionInt int
	}
	result, err := json.Marshal(versionInfo{versionReadable, versionInt})
	helper.Check(err)
	_, _ = w.Write(result)
}
func apiConfigInfo(w http.ResponseWriter, _ requestParser, _ models.User, _ models.ApiKey) {
	type configInfo struct {
		MaxFilesize               int
		MaxChunksize              int
		EndToEndEncryptionEnabled bool
	}
	config := configuration.Get()
	result, err := json.Marshal(configInfo{
		MaxFilesize:               config.MaxFileSizeMB,
		MaxChunksize:              config.ChunkSize,
		EndToEndEncryptionEnabled: config.Encryption.Level == encryption.EndToEndEncryption,
	})
	helper.Check(err)
	_, _ = w.Write(result)
}

// apiGetFeatures returns the server's current effective capability set (see the features
// package). Authenticated like every other /api/* route, but not gated on a specific
// permission - it carries no per-user data, only server-wide flags.
func apiGetFeatures(w http.ResponseWriter, _ requestParser, _ models.User, _ models.ApiKey) {
	result, err := json.Marshal(struct {
		Features features.Features `json:"features"`
	}{Features: features.Get()})
	helper.Check(err)
	_, _ = w.Write(result)
}

func apiList(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesListAll)
	if !ok {
		panic("invalid parameter passed")
	}
	validFiles := getFilesForUser(user, request.ShowFileRequests)
	result, err := json.Marshal(validFiles)
	helper.Check(err)
	_, _ = w.Write(result)
}

// getFilesForUser lists every file the caller may see, including one whose content has already
// been disposed of: retention keeps that record around specifically so its owner can still see
// it as history, so unlike storage.GetFile - which every public path resolves a file through and
// which does refuse a disposed record - this omits nothing past the ownership/permission and
// file-request checks below.
func getFilesForUser(user models.User, includeUploadRequests bool) []models.FileApiOutput {
	var validFiles []models.FileApiOutput
	config := configuration.Get()
	var collaborated map[string]bool
	if includeUploadRequests {
		collaborated = collaboratedRequestIds(user)
	}
	// One read of the folder table for the whole list: a folder decides its members' status, and
	// resolving that per file would read the same folder once per member of it.
	resolver := storage.NewDownloadAccessResolver()
	for _, element := range database.GetAllMetadata() {
		if !includeUploadRequests && element.IsFileRequest() {
			continue
		}
		if mayViewFile(element, user, collaborated) {
			file, err := element.ToFileApiOutput(config.ServerUrl, config.IncludeFilename, resolver.Of(element))
			helper.Check(err)
			validFiles = append(validFiles, file)
		}
	}
	// Sort by UploadDate descending, then by Id ascending for stable ordering
	sort.Slice(validFiles, func(i, j int) bool {
		if validFiles[i].UploadDate != validFiles[j].UploadDate {
			return validFiles[i].UploadDate > validFiles[j].UploadDate
		}
		return validFiles[i].Id < validFiles[j].Id
	})
	return validFiles
}

func apiListSingle(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesListSingle)
	if !ok {
		panic("invalid parameter passed")
	}
	file, ok := storage.GetFile(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "File not found")
		return
	}
	if !mayViewFile(file, user, nil) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to view file")
		return
	}
	config := configuration.Get()
	output, err := file.ToFileApiOutput(config.ServerUrl, config.IncludeFilename, storage.DownloadAccessOf(file))
	helper.Check(err)
	result, err := json.Marshal(output)
	helper.Check(err)
	_, _ = w.Write(result)
}

// apiGetShareKey returns the decrypted share password stored for a file, if
// the caller is authorised to view that file and one was actually stored. Authorisation mirrors
// apiListSingle above exactly (owner, or the list-other-uploads permission) - the same "may see
// this file at all" check the rest of the file-list/view surface uses, not a bit invented for
// this endpoint.
//
// Every refusal reason - caller not authorised, unknown file id, feature toggle off, nothing
// stored - answers with the same not-found response. Distinguishing any of them would let a
// caller probe, e.g., whether a file exists or has a stored key at all. A sealed instance is the
// one deliberate exception, answering 503 further down, so an administrator can tell "retry after
// unsealing" apart from "there was never a key here".
func apiGetShareKey(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesShareKey)
	if !ok {
		panic("invalid parameter passed")
	}
	file, ok := storage.GetFile(request.Id)
	if !ok || (file.UserId != user.Id && !user.HasPermission(models.UserPermListOtherUploads)) {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "File not found")
		return
	}
	// Checked explicitly, ahead of GetSharePassword: that call already fails safe while sealed
	// (encryption.DecryptString refuses once encryption.IsDecryptionAvailable is false), but it
	// reports that the same way as "no key was ever stored for this file" - a 404. An admin
	// polling this endpoint while sealed needs to be able to tell "sealed, try again after
	// unsealing" apart from "there was never a key to retrieve here".
	if encryption.IsSealed() {
		sendError(w, http.StatusServiceUnavailable, errorcodes.InstanceSealed, "Instance is sealed")
		return
	}
	password, ok := storage.GetSharePassword(file)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "File not found")
		return
	}
	result, err := json.Marshal(struct {
		Key string `json:"key"`
	}{Key: password})
	helper.Check(err)
	_, _ = w.Write(result)
}

// apiGetFolderShareKey returns the decrypted share password stored for a bundle (folder), if the
// caller is authorised to view that bundle and one was actually stored. Mirrors apiGetShareKey
// exactly - same authorisation (owner, or the list-other-uploads permission, matching
// apiFolderList), same collapsed not-found response for every refusal reason, same sealed-instance
// exception - see that function's doc comment for the full reasoning, which applies unchanged here.
func apiGetFolderShareKey(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFolderShareKey)
	if !ok {
		panic("invalid parameter passed")
	}
	bundle, ok := database.GetFileBundle(request.Id)
	if !ok || (bundle.UserId != user.Id && !user.HasPermission(models.UserPermListOtherUploads)) {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Folder not found")
		return
	}
	if encryption.IsSealed() {
		sendError(w, http.StatusServiceUnavailable, errorcodes.InstanceSealed, "Instance is sealed")
		return
	}
	password, ok := storage.GetBundleSharePassword(bundle)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Folder not found")
		return
	}
	result, err := json.Marshal(struct {
		Key string `json:"key"`
	}{Key: password})
	helper.Check(err)
	_, _ = w.Write(result)
}

func apiDownloadSingle(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesDownloadSingle)
	if !ok {
		panic("invalid parameter passed")
	}
	file, statusCode, errCode, errMessage := checkDownloadAllowed(request.Id, user)
	if statusCode != 0 {
		// Covers an unknown/expired file id as well as a permission denial; both are recorded,
		// attributed to the authenticated API user rather than as an anonymous share access.
		if auditErr := logging.LogDownloadDenied(models.File{Id: request.Id}, logging.WithActor(request.WebRequest, user), configuration.Get().SaveIp, errMessage); auditErr != nil {
			sendError(w, http.StatusServiceUnavailable, errorcodes.UnspecifiedError, "could not record audit event, request refused")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		sendError(w, statusCode, errCode, errMessage)
		return
	}
	if !request.PresignUrl {
		forceDecryption := file.Encryption.IsEncrypted && !file.Encryption.IsEndToEndEncrypted
		// Attribute the audit entry for this download to the authenticated API user rather
		// than recording it as an anonymous share access.
		storage.ServeFile(file, w, logging.WithActor(request.WebRequest, user), true, request.IncreaseCounter, forceDecryption, false)
		return
	}
	createAndOutputPresignedUrl([]string{file.Id}, w, "")
}

func apiDownloadZip(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesDownloadZip)
	if !ok {
		panic("invalid parameter passed")
	}
	requestedFiles := make([]models.File, 0)
	requestedFileIds := make([]string, 0)
	for _, fileId := range request.Ids {
		file, statusCode, errCode, errMessage := checkDownloadAllowed(fileId, user)
		if statusCode != 0 {
			// Covers an unknown/expired file id as well as a permission denial; both are
			// recorded, attributed to the authenticated API user rather than as an anonymous
			// share access.
			if auditErr := logging.LogDownloadDenied(models.File{Id: fileId}, logging.WithActor(request.WebRequest, user), configuration.Get().SaveIp, errMessage); auditErr != nil {
				sendError(w, http.StatusServiceUnavailable, errorcodes.UnspecifiedError, "could not record audit event, request refused")
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			sendError(w, statusCode, errCode, errMessage)
			return
		}
		requestedFiles = append(requestedFiles, file)
		requestedFileIds = append(requestedFileIds, file.Id)
	}
	if !request.PresignUrl {
		// Attribute the audit entry for each download in this zip to the authenticated API
		// user rather than recording it as an anonymous share access.
		storage.ServeFilesAsZip(requestedFiles, request.Filename, w, logging.WithActor(request.WebRequest, user))
		return
	}
	createAndOutputPresignedUrl(requestedFileIds, w, request.Filename)
}

// mayViewFileRequest reports whether user may see the request and what it collected: its owner,
// one of its collaborators (models.FileRequest.Collaborators), or a user who may list other
// people's uploads. Read side only. Every write path keeps its own owner-or-permission check,
// which is what makes a collaborator view-and-download and nothing more.
func mayViewFileRequest(fr models.FileRequest, user models.User) bool {
	return fr.UserId == user.Id || fr.IsCollaborator(user.Id) || user.HasPermission(models.UserPermListOtherUploads)
}

// mayViewFile reports whether user may list or download the file: its owner, a user who may list
// other people's uploads, or - for a file collected through a request - a collaborator on that
// request. collaboratedRequests is the caller's precomputed set from collaboratedRequestIds, so
// listing a thousand files does not fetch the request per file; pass nil when checking one file
// and the request is looked up here.
func mayViewFile(file models.File, user models.User, collaboratedRequests map[string]bool) bool {
	if file.UserId == user.Id || user.HasPermission(models.UserPermListOtherUploads) {
		return true
	}
	if !file.IsFileRequest() {
		return false
	}
	if collaboratedRequests != nil {
		return collaboratedRequests[file.UploadRequestId]
	}
	fr, ok := database.GetFileRequest(file.UploadRequestId)
	return ok && fr.IsCollaborator(user.Id)
}

// collaboratedRequestIds returns the id of every request user collaborates on.
func collaboratedRequestIds(user models.User) map[string]bool {
	result := make(map[string]bool)
	for _, fr := range database.GetAllFileRequests() {
		if fr.IsCollaborator(user.Id) {
			result[fr.Id] = true
		}
	}
	return result
}

// userMap returns every user keyed by id, for resolving display names in one lookup per call.
func userMap() map[int]models.User {
	result := make(map[int]models.User)
	for _, u := range database.GetAllUsers() {
		result[u.Id] = u
	}
	return result
}

// fillFileRequestNames sets OwnerName and each collaborator's Name from users. Neither is
// persisted (see the model). An account that no longer exists is shown as "unknown user" rather
// than dropped, so the id stays visible to whoever is cleaning up.
func fillFileRequestNames(fr *models.FileRequest, users map[int]models.User) {
	const unknown = "unknown user"
	if owner, ok := users[fr.UserId]; ok {
		fr.OwnerName = owner.Name
	} else {
		fr.OwnerName = unknown
	}
	for i, c := range fr.Collaborators {
		if u, ok := users[c.Id]; ok {
			fr.Collaborators[i].Name = u.Name
		} else {
			fr.Collaborators[i].Name = unknown
		}
	}
}

func checkDownloadAllowed(fileId string, user models.User) (models.File, int, int, string) {
	file, ok := storage.GetFile(fileId)
	if !ok {
		return models.File{}, http.StatusNotFound, errorcodes.NotFound, "file not found"
	}
	if !mayViewFile(file, user, nil) {
		return models.File{}, http.StatusUnauthorized, errorcodes.NoPermission, "no permission to download file"
	}
	return file, 0, 0, ""
}

func createAndOutputPresignedUrl(ids []string, w http.ResponseWriter, filename string) {
	presignUrl := models.Presign{
		Id:       helper.GenerateRandomString(60),
		FileIds:  ids,
		Expiry:   time.Now().Add(time.Second * 30).Unix(),
		Filename: filename,
	}
	presign.Save(presignUrl)
	response := struct {
		Result      string `json:"Result"`
		DownloadUrl string `json:"downloadUrl"`
	}{"OK", configuration.Get().ServerUrl + "downloadPresigned?key=" + presignUrl.Id}
	result, err := json.Marshal(response)
	helper.Check(err)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_, _ = w.Write(result)
}

func apiUploadFile(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesAdd)
	if !ok {
		panic("invalid parameter passed")
	}
	maxUpload := int64(configuration.Get().MaxFileSizeMB) * 1024 * 1024
	if request.Request.ContentLength > maxUpload {
		sendError(w, http.StatusBadRequest, errorcodes.FileTooLarge, storage.ErrorFileTooLarge.Error())
		return
	}

	request.Request.Body = http.MaxBytesReader(w, request.Request.Body, maxUpload)
	err := fileupload.ProcessCompleteFile(w, request.Request, user.Id, configuration.Get().MaxMemory)
	if err != nil {
		if errors.Is(err, storage.ErrorInstanceSealed) {
			sendError(w, http.StatusServiceUnavailable, errorcodes.InstanceSealed, err.Error())
			return
		}
		sendError(w, http.StatusBadRequest, errorcodes.UnspecifiedError, err.Error())
		return
	}
}

func apiDuplicateFile(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesDuplicate)
	if !ok {
		panic("invalid parameter passed")
	}
	file, ok := storage.GetFile(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid id provided.")
		return
	}
	if file.UserId != user.Id && !user.HasPermission(models.UserPermListOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to duplicate this file")
		return
	}
	uploadConfig, err := fileupload.CreateUploadConfig(request.AllowedDownloads,
		request.ExpiryDays,
		0, // a duplicate has no timestamp of its own to offer; it clamps by day count like the original upload did
		request.Password,
		request.UnlimitedTime,
		request.UnlimitedDownloads,
		false, // is not being used by storage.DuplicateFile
		0,     // is not being used by storage.DuplicateFile
		"",
		"",
		false) // a duplicated password is never treated as freshly auto-generated
	if err != nil {
		sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
		return
	}
	uploadConfig.UserId = user.Id
	newFile, err := storage.DuplicateFile(file, request.RequestedChanges, request.FileName, uploadConfig)
	if err != nil {
		if errors.Is(err, configuration.ErrSharePasswordTooShort) {
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
			return
		}
		sendError(w, http.StatusInternalServerError, errorcodes.InternalServer, err.Error())
		return
	}
	outputFileApiInfo(w, newFile)
}

func apiChangeFileOwner(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramFilesChangeOwner)
	if !ok {
		panic("invalid parameter passed")
	}

	apimutex.Lock(apimutex.TypeMetaData, request.Id)
	defer apimutex.Unlock(apimutex.TypeMetaData, request.Id)

	file, ok := storage.GetFile(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid id provided.")
		return
	}
	if !user.HasPermission(models.UserPermEditOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to edit this file")
		return
	}
	_, exists := database.GetUser(request.NewOwner)
	if !exists {
		sendError(w, http.StatusBadRequest, errorcodes.NotFound, "User does not exist")
		return
	}
	file.UserId = request.NewOwner
	database.SaveMetaData(file)
	outputFileApiInfo(w, file)
}

func apiReplaceFile(w http.ResponseWriter, r requestParser, user models.User, apikey models.ApiKey) {
	request, ok := r.(*paramFilesReplace)
	if !ok {
		panic("invalid parameter passed")
	}
	fileOriginal, ok := storage.GetFile(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid id provided.")
		return
	}
	if fileOriginal.UserId != user.Id && !user.HasPermission(models.UserPermReplaceOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to replace this file")
		return
	}

	if fileOriginal.IsFileRequest() {
		sendError(w, http.StatusBadRequest, errorcodes.UnsupportedFile, "Cannot replace a file request upload")
		return
	}
	fileNewContent, ok := storage.GetFile(request.IdNewContent)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid id provided.")
		return
	}
	if fileNewContent.UserId != user.Id && !user.HasPermission(models.UserPermListOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to duplicate this file")
		return
	}

	if request.DeleteNewFile &&
		(!apikey.HasPermissionDelete() ||
			(fileNewContent.UserId != user.Id && !user.HasPermission(models.UserPermDeleteOtherUploads))) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to delete original file")
		return
	}

	modifiedFile, err := storage.ReplaceFile(request.Id, request.IdNewContent, request.DeleteNewFile)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrorReplaceE2EFile):
			sendError(w, http.StatusBadRequest, errorcodes.EndToEndNotSupported, "End-to-End encrypted files cannot be replaced")
		case errors.Is(err, storage.ErrorFileNotFound):
			sendError(w, http.StatusNotFound, errorcodes.NotFound, "A file with such an ID could not be found")
		default:
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
		}
		return
	}
	logging.LogReplace(fileOriginal, modifiedFile, user)
	outputFileApiInfo(w, modifiedFile)
}

func outputFileApiInfo(w http.ResponseWriter, file models.File) {
	config := configuration.Get()
	publicOutput, err := file.ToFileApiOutput(config.ServerUrl, config.IncludeFilename, storage.DownloadAccessOf(file))
	helper.Check(err)
	result, err := json.Marshal(publicOutput)
	helper.Check(err)
	_, _ = w.Write(result)
}

func outputFileJson(w http.ResponseWriter, file models.File) {
	if w == nil {
		return
	}
	config := configuration.Get()
	_, _ = io.WriteString(w, file.ToJsonResult(config.ServerUrl, config.IncludeFilename, storage.DownloadAccessOf(file)))
}

// apiModifyUser applies whichever of a rank change, a permission grant/revoke, and a password
// reset the request carries - see paramUserModify. All three used to be separate endpoints, each
// re-deriving its own copy of the same guard; canAdministerUser now covers all of them in one
// place, so every mutation this handler can make is subject to it.
func apiModifyUser(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramUserModify)
	if !ok {
		panic("invalid parameter passed")
	}
	idStr := strconv.Itoa(request.Id)
	apimutex.Lock(apimutex.TypeUser, idStr)
	defer apimutex.Unlock(apimutex.TypeUser, idStr)

	userEdit, ok := isValidUserForEditing(w, request.Id)
	if !ok {
		return
	}
	if !canAdministerUser(user, userEdit) {
		sendError(w, http.StatusBadRequest, errorcodes.ResourceCanNotBeEdited, "Cannot modify this user")
		return
	}
	if request.IsPermissionSet {
		if request.GrantPermission && !user.HasPermission(request.Permission) {
			sendError(w, http.StatusBadRequest, errorcodes.NoPermission, "Cannot grant rights the user does not have")
			return
		}
		// Symmetric with granting: revoking a bit the actor does not themselves hold would let a
		// rank-2 user with only UserPermManageUsers strip an admin's capabilities one bit at a time.
		if !request.GrantPermission && !user.HasPermission(request.Permission) {
			sendError(w, http.StatusBadRequest, errorcodes.NoPermission, "Cannot revoke rights the user does not have")
			return
		}
	}
	if request.ResetPassword && userEdit.AuthProvider != models.AuthProviderInternal {
		// Refuse to set or generate a password for a user not provisioned for internal auth. An
		// admin minting a password for an SSO colleague's account would bypass the IdP entirely -
		// its MFA and deprovisioning - the moment the row has a password hash, since a non-empty
		// hash used to be the only gate IsCorrectUsernameAndPassword checked.
		sendError(w, http.StatusBadRequest, errorcodes.ResourceCanNotBeEdited, "Cannot reset password of a user provisioned for external authentication")
		return
	}

	if request.IsRankSet {
		userEdit.UserLevel = request.NewRank
		switch request.NewRank {
		case models.UserLevelAdmin:
			userEdit.Permissions = models.UserPermissionAll
		case models.UserLevelUser:
			userEdit.Permissions = models.UserPermissionNone
			updateApiKeyPermsOnUserPermChange(userEdit.Id, models.UserPermReplaceUploads)
			updateApiKeyPermsOnUserPermChange(userEdit.Id, models.UserPermManageUsers)
			updateApiKeyPermsOnUserPermChange(userEdit.Id, models.UserPermManageLogs)
			updateApiKeyPermsOnUserPermChange(userEdit.Id, models.UserPermGuestUploads)
		}
	}
	if request.IsPermissionSet {
		if request.GrantPermission {
			if !userEdit.HasPermission(request.Permission) {
				userEdit.GrantPermission(request.Permission)
			}
		} else if userEdit.HasPermission(request.Permission) {
			userEdit.RemovePermission(request.Permission)
			updateApiKeyPermsOnUserPermChange(userEdit.Id, request.Permission)
		}
	}
	newPassword := ""
	if request.ResetPassword {
		userEdit.ResetPassword = true
		if request.GenerateNewPassword {
			newPassword = helper.GenerateRandomPassword(configuration.GetEnvironment().MinLengthPassword + 2)
			userEdit.Password = configuration.HashPassword(newPassword, false, "")
		}
		database.DeleteAllSessionsByUser(userEdit.Id)
	}

	logging.LogUserEdit(userEdit, user)
	database.SaveUser(userEdit, false)

	if request.ResetPassword {
		resultStruct := struct {
			Result      string `json:"Result"`
			NewPassword string `json:"password"`
		}{Result: "OK", NewPassword: newPassword}
		result, _ := json.Marshal(resultStruct)
		_, _ = w.Write(result)
	}
}

func updateApiKeyPermsOnUserPermChange(userId int, userPerm models.UserPermission) {
	var affectedPermission models.ApiPermission
	switch userPerm {
	case models.UserPermManageUsers:
		affectedPermission = models.ApiPermManageUsers
	case models.UserPermReplaceUploads:
		affectedPermission = models.ApiPermReplace
	case models.UserPermManageLogs:
		affectedPermission = models.ApiPermManageLogs
	case models.UserPermGuestUploads:
		affectedPermission = models.ApiPermManageFileRequests
	default:
		return
	}
	for _, apiKey := range database.GetAllApiKeys() {
		if apiKey.UserId != userId {
			continue
		}
		if apiKey.HasPermission(affectedPermission) {
			apiKey.RemovePermission(affectedPermission)
			database.SaveApiKey(apiKey)
		}
	}
}

// apiSetShareRecipients shares a resource with a list of email addresses,
// setting its list to exactly the addresses given. An empty list clears it,
// which returns the resource to its previous anonymous access mode.
//
// The list is replaced from the caller's point of view, but an address that
// appears in both the old list and the new one keeps the grant it already
// holds. Adding one address is not allowed to refund the ones already there.
//
// The uploader must own the resource, or hold the permission to edit other
// people's uploads. Granting someone access to a file is a change to that
// file, so it is gated exactly as editing it is.
func apiSetShareRecipients(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramShareRecipients)
	if !ok {
		panic("invalid parameter passed")
	}

	resource, ok := resolveShareResource(w, request.ResourceType, request.ResourceId, user)
	if !ok {
		return
	}

	// Clearing the list needs no mail connector, only granting does, so the
	// empty case is handled before the fail-closed check in GrantAccess.
	if len(request.Emails) == 0 {
		database.DeleteShareGrants(request.ResourceType, request.ResourceId)
		logging.LogShareRecipientsCleared(request.ResourceType, request.ResourceId, user)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		_, _ = io.WriteString(w, `{"result":"OK","recipients":[]}`)
		return
	}

	results, err := shareaccess.GrantAccess(resource, request.Emails, user,
		request.DownloadsAllowed, configuration.Get().ServerUrl)
	if err != nil {
		if errors.Is(err, shareaccess.ErrMailNotConfigured) {
			sendError(w, http.StatusPreconditionFailed, errorcodes.NoPermission, err.Error())
			return
		}
		sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, err.Error())
		return
	}
	logging.LogShareRecipientsGranted(request.ResourceType, request.ResourceId, len(results), user)

	type recipientOutput struct {
		Email          string `json:"email"`
		IsNewRecipient bool   `json:"isNewRecipient"`
		MailError      string `json:"mailError,omitempty"`
	}
	output := make([]recipientOutput, 0, len(results))
	for _, result := range results {
		entry := recipientOutput{Email: result.Email, IsNewRecipient: result.IsNewRecipient}
		if result.MailErr != nil {
			// The grant was still created, so the uploader can resend rather
			// than rebuild the share. Reporting the failure per address is what
			// lets them see which one needs it.
			entry.MailError = result.MailErr.Error()
		}
		output = append(output, entry)
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"result": "OK", "recipients": output})
}

// apiListShareRecipients returns the addresses a resource is shared with,
// along with how much of their allowance each has used.
func apiListShareRecipients(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramShareRecipientsList)
	if !ok {
		panic("invalid parameter passed")
	}
	if _, ok := resolveShareResource(w, request.ResourceType, request.ResourceId, user); !ok {
		return
	}

	type recipientOutput struct {
		Email            string `json:"email"`
		DownloadsUsed    int    `json:"downloadsUsed"`
		DownloadsAllowed int    `json:"downloadsAllowed"`
		LastDownloadAt   int64  `json:"lastDownloadAt"`
		IsBlocked        bool   `json:"isBlocked"`
	}
	output := make([]recipientOutput, 0)
	for _, grant := range database.GetShareGrants(request.ResourceType, request.ResourceId) {
		recipient, found := database.GetShareRecipient(grant.RecipientId)
		if !found {
			continue
		}
		output = append(output, recipientOutput{
			Email:            recipient.Email,
			DownloadsUsed:    grant.DownloadsUsed,
			DownloadsAllowed: grant.DownloadsAllowed,
			LastDownloadAt:   grant.LastDownloadAt,
			IsBlocked:        recipient.IsBlocked,
		})
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"result": "OK", "recipients": output})
}

// apiShareRecipientsSummary returns who every resource the caller can see is
// shared with, in one call.
//
// The file list needs this per row. Asking /share/recipients/list per row would
// be one request per file, so the walk here is driven off the recipient index
// instead: an install shares with far fewer addresses than it holds resources,
// and grants are already indexed by recipient.
func apiShareRecipientsSummary(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	type recipientOutput struct {
		Email            string `json:"email"`
		DownloadsUsed    int    `json:"downloadsUsed"`
		DownloadsAllowed int    `json:"downloadsAllowed"`
		LastDownloadAt   int64  `json:"lastDownloadAt"`
		IsBlocked        bool   `json:"isBlocked"`
	}
	type shareOutput struct {
		ResourceType int               `json:"resourceType"`
		ResourceId   string            `json:"resourceId"`
		Recipients   []recipientOutput `json:"recipients"`
	}
	type resourceKey struct {
		resourceType int
		resourceId   string
	}

	grouped := make(map[resourceKey][]recipientOutput)
	// A resource carrying several recipients would otherwise be re-resolved
	// once per recipient.
	visible := make(map[resourceKey]bool)
	for _, recipient := range database.GetAllShareRecipients() {
		for _, grant := range database.GetShareGrantsForRecipient(recipient.Id) {
			key := resourceKey{grant.ResourceType, grant.ResourceId}
			isVisible, checked := visible[key]
			if !checked {
				isVisible = mayUserSeeShareRecipients(grant.ResourceType, grant.ResourceId, user)
				visible[key] = isVisible
			}
			if !isVisible {
				continue
			}
			grouped[key] = append(grouped[key], recipientOutput{
				Email:            recipient.Email,
				DownloadsUsed:    grant.DownloadsUsed,
				DownloadsAllowed: grant.DownloadsAllowed,
				LastDownloadAt:   grant.LastDownloadAt,
				IsBlocked:        recipient.IsBlocked,
			})
		}
	}

	output := make([]shareOutput, 0, len(grouped))
	for key, recipients := range grouped {
		output = append(output, shareOutput{
			ResourceType: key.resourceType,
			ResourceId:   key.resourceId,
			Recipients:   recipients,
		})
	}
	// Map iteration order is random, so without this the same data would
	// serialise differently on every call.
	sort.Slice(output, func(i, j int) bool {
		if output[i].ResourceType != output[j].ResourceType {
			return output[i].ResourceType < output[j].ResourceType
		}
		return output[i].ResourceId < output[j].ResourceId
	})

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"result": "OK", "shares": output})
}

// apiShareInbox lists every share the caller may open because a ShareRecipient row's email
// matches the caller's own account name.
//
// This is derived, not materialised: there is no inbox table, so every call resolves the one
// recipient row for user.Name and walks its grants live. That is also why the list is correct
// the instant a grant is created, cleared or blocked, with nothing to invalidate. A blocked
// recipient, or an account whose name is not an email (so it can never match a recipient row -
// internal accounts like "admin" are the only ones affected, and they have no email to begin
// with), simply gets an empty list rather than an error.
//
// Per grant, the resource is re-resolved through the same accessor resolveShareResource uses for
// each type and excluded on the same conditions that make resolveShareResource itself report
// "not found": a file that is disposed or past its own expiry, or a file request that is closed
// or past its expiry. This is a safety net independent of the grant-cascade cleanup: it protects
// against a grant row that outlived its resource for any reason, not only the ones the cascade
// deletes deliberately. Requires API permission VIEW.
func apiShareInbox(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	type inboxItem struct {
		ResourceType     int    `json:"resourceType"`
		ResourceId       string `json:"resourceId"`
		Name             string `json:"name"`
		SharedBy         string `json:"sharedBy"`
		SharedAt         int64  `json:"sharedAt"`
		ExpiresAt        int64  `json:"expiresAt"`
		DownloadsUsed    int    `json:"downloadsUsed"`
		DownloadsAllowed int    `json:"downloadsAllowed"`
		LastDownloadAt   int64  `json:"lastDownloadAt"`
		Size             int64  `json:"size"`
	}

	items := make([]inboxItem, 0)
	recipient, found := database.GetShareRecipientByEmail(database.NormaliseRecipientEmail(user.Name))
	if !found || recipient.IsBlocked {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": "OK", "items": items})
		return
	}

	timeNow := time.Now().Unix()
	leeway := int64(storage.DownloadLeeway().Seconds())
	// GrantedBy resolves to a user id far more often than to distinct ids across one inbox, so a
	// small cache keeps a page of results from repeating database.GetUser per row.
	grantedByNames := make(map[int]string)

	for _, grant := range database.GetShareGrantsForRecipient(recipient.Id) {
		var name string
		var expiresAt int64
		var size int64
		// grantLeeway is how long a download window stays open for this resource, which is what
		// decides when a recipient who has spent their allowance actually stops seeing it - see
		// the filter below. A secret has none, so it leaves the inbox the moment it is read.
		grantLeeway := leeway

		switch grant.ResourceType {
		case models.ShareResourceFile:
			file, ok := database.GetMetaDataById(grant.ResourceId)
			if !ok || file.IsDisposed() || (!file.UnlimitedTime && file.ExpireAt < timeNow) {
				continue
			}
			name = file.Name
			expiresAt = shareExpiry(file.UnlimitedTime, file.ExpireAt)
			size = file.SizeBytes
			grantLeeway = int64(storage.LeewayFor(file).Seconds())
		case models.ShareResourceBundle:
			bundle, ok := database.GetFileBundle(grant.ResourceId)
			// A folder is the unit of sharing, so the expiry and allowance governing it decide
			// whether there is anything left to open - the same test pubApiFolder applies.
			// Without this an exhausted or expired folder stayed listed alongside the files,
			// which are filtered just below.
			if !ok || !storage.IsAvailableBundle(bundle, timeNow) {
				continue
			}
			name = bundle.DisplayName()
			expiresAt = shareExpiry(bundle.UnlimitedTime, bundle.ExpireAt)
		case models.ShareResourceFileRequest:
			fileRequest, ok := database.GetFileRequest(grant.ResourceId)
			if !ok || fileRequest.Closed || fileRequest.IsExpired() {
				continue
			}
			name = fileRequest.DisplayName()
			expiresAt = fileRequest.Expiry
		default:
			continue
		}

		// A recipient who has spent their own allowance is finished with this resource and stops
		// seeing it entirely, while every other recipient's own budget carries on. Listing it
		// anyway offered an Open link that could only fail - see models.ShareGrant.IsExhausted,
		// which is the same rule the download itself is refused by, window included: a broken
		// transfer can still be retried while that window is open, so the row survives with it.
		if grant.IsExhausted(timeNow, grantLeeway) {
			continue
		}

		sharedBy, cached := grantedByNames[grant.GrantedBy]
		if !cached {
			if grantedByUser, ok := database.GetUser(grant.GrantedBy); ok {
				sharedBy = grantedByUser.Name
			} else {
				sharedBy = "(deleted user)"
			}
			grantedByNames[grant.GrantedBy] = sharedBy
		}

		items = append(items, inboxItem{
			ResourceType:     grant.ResourceType,
			ResourceId:       grant.ResourceId,
			Name:             name,
			SharedBy:         sharedBy,
			SharedAt:         grant.GrantedAt,
			ExpiresAt:        expiresAt,
			DownloadsUsed:    grant.DownloadsUsed,
			DownloadsAllowed: grant.DownloadsAllowed,
			LastDownloadAt:   grant.LastDownloadAt,
			Size:             size,
		})
	}

	// Map iteration order inside GetShareGrantsForRecipient is not guaranteed stable across
	// providers, so without this the same data could serialise in a different order per call.
	sort.Slice(items, func(i, j int) bool {
		return items[i].SharedAt > items[j].SharedAt
	})

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"result": "OK", "items": items})
}

// apiShareInboxOpen exchanges the caller's own share grant for the recipient cookie the mailed
// link would have produced, then hands back the same public URL that link points at.
//
// It deliberately does not mint a new access token. shareaccess.WriteCookie only records an
// in-memory cookie entry against the recipient id the grant already names; unlike issueAndSend it
// never calls database.RevokeShareLoginTokens or database.SaveShareLoginToken. Minting a fresh
// token here - the obvious-looking alternative - would revoke the ShareLoginToken row backing
// the link already sitting in the recipient's mailbox as a side effect, breaking it the moment a
// signed-in caller opened the same share from their inbox. Reusing the cookie exchange keeps this
// endpoint from ever touching that row at all.
//
// A resource the caller holds no grant for, resolved with the same email match apiShareInbox
// uses, is reported as 404, matching resolveShareResource's non-enumerable stance: this endpoint
// cannot be used to probe which resource IDs exist. Requires API permission DOWNLOAD, since it
// issues a download-capable credential.
func apiShareInboxOpen(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramShareInboxOpen)
	if !ok {
		panic("invalid parameter passed")
	}

	recipient, found := database.GetShareRecipientByEmail(database.NormaliseRecipientEmail(user.Name))
	if !found || recipient.IsBlocked || !database.HasShareGrant(request.ResourceType, request.ResourceId, recipient.Id) {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid resource ID provided.")
		return
	}

	shareaccess.WriteCookie(w, request.Request, request.ResourceType, request.ResourceId, recipient.Id)
	logging.LogShareInboxOpened(request.ResourceType, request.ResourceId, user)

	url := fmt.Sprintf("/%s/%s", shareaccess.PathPrefix(request.ResourceType), request.ResourceId)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"result": "OK", "url": url})
}

// mayUserSeeShareRecipients reports whether the caller is allowed to know who a
// resource is shared with. Same rule as listing the resource itself: its owner,
// or a user who may list other people's uploads.
func mayUserSeeShareRecipients(resourceType int, resourceId string, user models.User) bool {
	switch resourceType {
	case models.ShareResourceFile:
		file, found := database.GetMetaDataById(resourceId)
		return found && (file.UserId == user.Id || user.HasPermission(models.UserPermListOtherUploads))
	case models.ShareResourceBundle:
		bundle, found := database.GetFileBundle(resourceId)
		return found && (bundle.UserId == user.Id || user.HasPermission(models.UserPermListOtherUploads))
	case models.ShareResourceFileRequest:
		fileRequest, found := database.GetFileRequest(resourceId)
		return found && mayViewFileRequest(fileRequest, user)
	default:
		return false
	}
}

// resolveShareResource looks up the resource and confirms the caller may change
// who can reach it.
//
// A caller who may not is told "not found" rather than "forbidden", so the
// endpoint cannot be used to discover which IDs exist. The same "not found" now also covers
// a resource that no longer exists in any usable sense - expired, exhausted, closed, or
// pending deletion - the same liveness check the public resend path applies in
// webserver.describeShareResource, so this path cannot be used to grant or list share access
// on a resource nobody can actually reach any more. For models.ShareResourceFile it also refuses
// a file received through a file request: its UserId is the request owner's, so ownership alone
// would otherwise pass, but every public consumption route (showDownload, showHotlink, serveFile,
// and the pubApi JSON handlers) refuses such a file outright, and a grant on one the owner could
// never actually deliver.
func resolveShareResource(w http.ResponseWriter, resourceType int, resourceId string, user models.User) (shareaccess.Resource, bool) {
	switch resourceType {
	case models.ShareResourceFile:
		// storage.GetFile refuses a file that is expired, exhausted, or pending deletion,
		// the same check the public file endpoint relies on to 404 for a dead file.
		file, found := storage.GetFile(resourceId)
		if !found || file.IsFileRequest() || (file.UserId != user.Id && !user.HasPermission(models.UserPermEditOtherUploads)) {
			sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid resource ID provided.")
			return shareaccess.Resource{}, false
		}
		return shareaccess.Resource{
			Type: resourceType, Id: resourceId, Name: file.Name,
			ExpiresAt: shareExpiry(file.UnlimitedTime, file.ExpireAt),
		}, true
	case models.ShareResourceBundle:
		bundle, found := database.GetFileBundle(resourceId)
		if !found || (bundle.UserId != user.Id && !user.HasPermission(models.UserPermEditOtherUploads)) {
			sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid resource ID provided.")
			return shareaccess.Resource{}, false
		}
		if !bundleHasOnlyLiveMembers(bundle.Id) {
			sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid resource ID provided.")
			return shareaccess.Resource{}, false
		}
		return shareaccess.Resource{Type: resourceType, Id: resourceId, Name: bundle.DisplayName()}, true
	case models.ShareResourceFileRequest:
		fileRequest, found := database.GetFileRequest(resourceId)
		if !found || (fileRequest.UserId != user.Id && !user.HasPermission(models.UserPermEditOtherUploads)) {
			sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid resource ID provided.")
			return shareaccess.Resource{}, false
		}
		if fileRequest.Closed || (!fileRequest.IsUnlimitedTime() && fileRequest.Expiry < time.Now().Unix()) {
			sendError(w, http.StatusNotFound, errorcodes.NotFound, "Invalid resource ID provided.")
			return shareaccess.Resource{}, false
		}
		return shareaccess.Resource{
			Type: resourceType, Id: resourceId, Name: fileRequest.DisplayName(),
			ExpiresAt: fileRequest.Expiry,
		}, true
	default:
		sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, "Unknown resource type.")
		return shareaccess.Resource{}, false
	}
}

// bundleHasOnlyLiveMembers reports whether every member of a bundle (see models.File.IsBundleMember)
// is currently servable - not expired, not exhausted. A bundle with no members, or with even one
// that is not servable, is not resolved by resolveShareResource. The servability check itself
// mirrors bundleAvailability in internal/webserver; membership is the shared predicate both packages
// use, so the two cannot independently drift on what counts as a member.
func bundleHasOnlyLiveMembers(bundleId string) bool {
	timeNow := time.Now().Unix()
	found := false
	for _, file := range database.GetAllMetadata() {
		if !file.IsBundleMember(bundleId) {
			continue
		}
		found = true
		if storage.IsExpiredFile(file, timeNow) {
			return false
		}
	}
	return found
}

// shareExpiry reports when the resource stops existing, or 0 when it never
// does. The access link is given the same lifetime, so it cannot outlive what
// it points at.
func shareExpiry(unlimitedTime bool, expireAt int64) int64 {
	if unlimitedTime {
		return 0
	}
	return expireAt
}

func apiDeleteUser(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramUserDelete)
	if !ok {
		panic("invalid parameter passed")
	}
	userToDelete, ok := isValidUserForEditing(w, request.Id)
	if !ok {
		return
	}
	if userToDelete.IsSuperAdmin() {
		sendError(w, http.StatusBadRequest, errorcodes.ResourceCanNotBeEdited, "Cannot delete super admin")
		return
	}
	if userToDelete.IsSameUser(user.Id) {
		sendError(w, http.StatusBadRequest, errorcodes.ResourceCanNotBeEdited, "Cannot delete yourself")
		return
	}
	logging.LogUserDeletion(userToDelete, user)

	database.DeleteAllSessionsByUser(userToDelete.Id)
	avatar.Delete(userToDelete.Id)

	for _, apiKey := range database.GetAllApiKeys() {
		if apiKey.UserId == userToDelete.Id {
			database.DeleteApiKey(apiKey.Id)
		}
	}

	database.DeleteEnd2EndInfo(userToDelete.Id)

	for _, fRequest := range database.GetAllFileRequests() {
		if fRequest.UserId == userToDelete.Id {
			if request.DeleteFiles {
				filerequest.Delete(fRequest)
			} else {
				fRequest.UserId = user.Id
				// The new owner may have been a collaborator; the roles never overlap.
				fRequest.SetCollaboratorIds(withoutId(fRequest.CollaboratorIds(), user.Id))
				database.SaveFileRequest(fRequest)
			}
			continue
		}
		if fRequest.IsCollaborator(userToDelete.Id) {
			fRequest.SetCollaboratorIds(withoutId(fRequest.CollaboratorIds(), userToDelete.Id))
			database.SaveFileRequest(fRequest)
		}
	}

	for _, file := range database.GetAllMetadata() {
		if file.UserId == userToDelete.Id {
			if request.DeleteFiles {
				// Routed through the normal dispose lifecycle rather than removing the metadata
				// row directly: that skipped storage.DeleteFile's blob deletion, hotlink cleanup
				// and share-token revocation entirely, and left the file's share grants behind.
				storage.DeleteFile(file.Id, true)
			} else {
				file.UserId = user.Id
				database.SaveMetaData(file)
			}
		}
	}
	database.DeleteUser(userToDelete.Id)
}

func apiLogsDelete(_ http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramLogsDelete)
	if !ok {
		panic("invalid parameter passed")
	}
	logging.DeleteLogs(user.Name, user.Id, request.Timestamp, request.Request)
}
func apiLogsGet(w http.ResponseWriter, r requestParser, _ models.User, _ models.ApiKey) {
	request, ok := r.(*paramLogsGet)
	if !ok {
		panic("invalid parameter passed")
	}
	result := struct {
		LogEntries string `json:"logEntries"`
		Timestamp  int64  `json:"timestamp"`
	}{}
	if request.Timestamp == 0 {
		result.LogEntries, _ = logging.GetAll()
	} else {
		result.LogEntries = logging.GetSince(request.Timestamp)
	}
	result.Timestamp = time.Now().Unix()
	resultJson, err := json.Marshal(result)
	helper.Check(err)
	_, _ = w.Write(resultJson)
}

func apiLogsAudit(w http.ResponseWriter, r requestParser, _ models.User, _ models.ApiKey) {
	request, ok := r.(*paramLogsAudit)
	if !ok {
		panic("invalid parameter passed")
	}
	// Convert int64 to uint64; negative values default to 0
	fromSeq := uint64(0)
	if request.FromSeq > 0 {
		fromSeq = uint64(request.FromSeq)
	}
	entries, lastSeq := logging.GetAuditEntriesSince(fromSeq, request.Limit)

	// Ensure we return an empty slice literal, not nil, so it marshals as [] not null
	if entries == nil {
		entries = []logging.AuditEntry{}
	}

	result := struct {
		Entries []logging.AuditEntry `json:"entries"`
		LastSeq uint64               `json:"lastSeq"`
	}{
		Entries: entries,
		LastSeq: lastSeq,
	}
	resultJson, err := json.Marshal(result)
	helper.Check(err)
	_, _ = w.Write(resultJson)
}

func apiLogSystemStatus(w http.ResponseWriter, _ requestParser, _ models.User, _ models.ApiKey) {
	result := struct {
		Uptime                int64  `json:"uptime"`
		TrafficRecordingSince int64  `json:"trafficRecordingSince"`
		CpuLoad               int    `json:"cpuLoad"`
		MemoryUsagePercentage int    `json:"memoryUsagePercentage"`
		DiskUsagePercentage   int    `json:"diskUsagePercentage"`
		ActiveFiles           int    `json:"activeFiles"`
		MemoryUsed            uint64 `json:"memoryUsed"`
		MemoryTotal           uint64 `json:"memoryTotal"`
		DiskUsed              uint64 `json:"diskUsed"`
		DiskTotal             uint64 `json:"diskTotal"`
		DataServed            uint64 `json:"dataServed"`
	}{
		Uptime:      serverstats.GetUptime(),
		CpuLoad:     serverstats.GetCpuUsage(),
		ActiveFiles: serverstats.GetTotalFiles(),
	}
	result.DataServed, result.TrafficRecordingSince = serverstats.GetCurrentTraffic()
	_, result.MemoryUsed, result.MemoryTotal, result.MemoryUsagePercentage = serverstats.GetMemoryInfo()
	_, result.DiskUsed, result.DiskTotal, result.DiskUsagePercentage = serverstats.GetDiskInfo()
	resultJson, err := json.Marshal(result)
	if err != nil {
		fmt.Println(err)
		sendError(w, http.StatusInternalServerError, errorcodes.InternalServer, err.Error())
		return
	}
	_, _ = w.Write(resultJson)
}

func apiLogResetTraffic(w http.ResponseWriter, _ requestParser, _ models.User, _ models.ApiKey) {
	serverstats.ClearTraffic()
	_, _ = w.Write([]byte(`{"Result":"OK"}`))
}

func apiE2eGet(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	if !e2emutex.IsLocked(user.Id) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("{\"result\":\"error\",\"errormessage\":\"mutex was not acquired or has expired\"}"))
		return
	}
	info := database.GetEnd2EndInfo(user.Id)
	// If e2e is supported for upload requests at some point, this needs to be changed
	files := getFilesForUser(user, false)
	ids := make([]string, len(files))
	for i, file := range files {
		ids[i] = file.Id
	}
	info.AvailableFiles = ids
	bytesE2e, err := json.Marshal(info)
	helper.Check(err)
	_, _ = w.Write(bytesE2e)
}

func apiE2eSet(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	if !e2emutex.IsLocked(user.Id) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("{\"result\":\"error\",\"errormessage\":\"mutex was not acquired or has expired\"}"))
		return
	}
	request, ok := r.(*paramE2eStore)
	if !ok {
		panic("invalid parameter passed")
	}
	database.SaveEnd2EndInfo(request.EncryptedInfo, user.Id)
	_, _ = w.Write([]byte("{\"result\":\"OK\"}"))
}
func apiE2eMutexLock(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	e2emutex.Lock(user.Id)
	_, _ = w.Write([]byte("{\"result\":\"OK\"}"))
}

func apiE2eMutexUnlock(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	e2emutex.Unlock(user.Id)
	_, _ = w.Write([]byte("{\"result\":\"OK\"}"))
}
func apiURequestDelete(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramURequestDelete)
	if !ok {
		panic("invalid parameter passed")
	}

	uploadRequest, ok := database.GetFileRequest(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "FileRequest does not exist with the given ID")
		return
	}
	if uploadRequest.UserId != user.Id && !user.HasPermission(models.UserPermDeleteOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to delete this upload request")
		return
	}
	filerequest.Delete(uploadRequest)
	logging.LogDeleteFileRequest(uploadRequest, user)
	_, _ = w.Write([]byte("{\"result\":\"OK\"}"))
}

// apiURequestCollaborators replaces the collaborator list of a file request. Owner only, or a
// user who may edit other people's uploads; a collaborator cannot change the list. Every id must
// name an existing account and the owner is refused, so the two roles never overlap.
func apiURequestCollaborators(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramURequestCollaborators)
	if !ok {
		panic("invalid parameter passed")
	}
	// Same guard as apiURequestSave: SaveFileRequest re-encrypts the name and note.
	if encryption.IsSealed() {
		sendError(w, http.StatusServiceUnavailable, errorcodes.InstanceSealed, "Instance is sealed")
		return
	}
	uploadRequest, ok := database.GetFileRequest(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "FileRequest does not exist with the given ID")
		return
	}
	if uploadRequest.UserId != user.Id && !user.HasPermission(models.UserPermEditOtherUploads) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to change the collaborators of this upload request")
		return
	}
	users := userMap()
	for _, id := range request.UserIds {
		if id == uploadRequest.UserId {
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, "The owner cannot be added as a collaborator")
			return
		}
		if _, exists := users[id]; !exists {
			sendError(w, http.StatusBadRequest, errorcodes.InvalidUserInput, fmt.Sprintf("User %d does not exist", id))
			return
		}
	}
	before := uploadRequest.CollaboratorIds()
	uploadRequest.SetCollaboratorIds(request.UserIds)
	database.SaveFileRequest(uploadRequest)
	added, removed := diffIds(before, uploadRequest.CollaboratorIds())
	logging.LogFileRequestCollaboratorsChanged(uploadRequest, user, added, removed)

	uploadRequest.Name = uploadRequest.DisplayName()
	fillFileRequestNames(&uploadRequest, users)
	result, err := json.Marshal(uploadRequest)
	helper.Check(err)
	_, _ = w.Write(result)
}

// diffIds returns what is in after but not before, and in before but not after.
func diffIds(before, after []int) (added, removed []int) {
	beforeSet := make(map[int]bool, len(before))
	for _, id := range before {
		beforeSet[id] = true
	}
	afterSet := make(map[int]bool, len(after))
	for _, id := range after {
		afterSet[id] = true
		if !beforeSet[id] {
			added = append(added, id)
		}
	}
	for _, id := range before {
		if !afterSet[id] {
			removed = append(removed, id)
		}
	}
	return added, removed
}

// withoutId returns ids with every occurrence of id removed.
func withoutId(ids []int, id int) []int {
	result := make([]int, 0, len(ids))
	for _, candidate := range ids {
		if candidate != id {
			result = append(result, candidate)
		}
	}
	return result
}

func isUserAllowedUnlimited(request *paramURequestSave, isNewRequest bool, user models.User) bool {
	if user.IsAdmin() {
		return true
	}
	isServerLimitMaxSize := configuration.GetEnvironment().MaxSizeGuestUploadMb != 0
	isServerLimitMaxFiles := configuration.GetEnvironment().MaxFilesGuestUpload != 0
	if isServerLimitMaxSize {
		if (request.IsMaxSizeSet || isNewRequest) &&
			(request.MaxSizeMb == 0 || request.MaxSizeMb > configuration.GetEnvironment().MaxSizeGuestUploadMb) {
			return false
		}
	}
	if isServerLimitMaxFiles {
		if (request.IsMaxFilesSet || isNewRequest) &&
			(request.MaxFiles == 0 || request.MaxFiles > configuration.GetEnvironment().MaxFilesGuestUpload) {
			return false
		}
	}

	return true
}

func apiURequestSave(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramURequestSave)
	if !ok {
		panic("invalid parameter passed")
	}
	// database.SaveFileRequest needs the master key to encrypt the name and note (see
	// encryptRequestNameForSave/encryptNoteForSave). Checked here rather than left to fail inside
	// it: an ErrSealed there would reach helper.Check and panic the request instead of answering
	// with a clean refusal, the same way ServeFile refuses a sealed instance.
	if encryption.IsSealed() {
		sendError(w, http.StatusServiceUnavailable, errorcodes.InstanceSealed, "Instance is sealed")
		return
	}
	uploadRequest := models.FileRequest{}
	isNewRequest := request.Id == ""

	if !isUserAllowedUnlimited(request, isNewRequest, user) {
		sendError(w, http.StatusBadRequest, errorcodes.AdminOnly, "Only admin users can create requests with unlimited size / file count"+
			" or values larger than the server's max size / file count")
		return
	}

	if !isNewRequest {
		uploadRequest, ok = database.GetFileRequest(request.Id)
		if !ok {
			sendError(w, http.StatusNotFound, errorcodes.NotFound, "FileRequest does not exist with the given ID")
			return
		}
		if uploadRequest.UserId != user.Id && !user.HasPermission(models.UserPermEditOtherUploads) {
			sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to edit this upload request")
			return
		}
	} else {
		uploadRequest = filerequest.New(user)
		apiKey := generateNewKey(false, user.Id, "File Request Public Access", uploadRequest.Id)
		uploadRequest.ApiKey = apiKey.Id
	}
	wasClosed := uploadRequest.Closed

	if request.Name == "" {
		if request.IsNameSet || uploadRequest.Name == "" {
			uploadRequest.Name = "Unnamed Request"
		}
	} else {
		uploadRequest.Name = request.Name
	}
	if request.IsExpirySet {
		// A file request's Expiry of 0 means unlimited (see models.FileRequest.IsUnlimitedTime),
		// so that is exactly the unlimitedTime signal ClampExpiryTimestamp needs. Without this
		// call a request could be saved with an expiry beyond GOKAPI_MAX_EXPIRY, or with no
		// expiry at all, the same gap apiFilesModify closed for single files below.
		uploadRequest.Expiry, _ = fileupload.ClampExpiryTimestamp(request.Expiry, request.Expiry == 0)
	}
	if request.IsMaxFilesSet {
		uploadRequest.MaxFiles = request.MaxFiles
	}
	if request.IsMaxSizeSet {
		uploadRequest.MaxSize = request.MaxSizeMb
	}
	if request.IsNotesSet {
		uploadRequest.Notes = request.Notes
	}
	if request.IsClosedSet {
		if request.Closed && !wasClosed {
			uploadRequest.ClosedAt = time.Now().Unix()
		} else if !request.Closed {
			uploadRequest.ClosedAt = 0
		}
		uploadRequest.Closed = request.Closed
	}
	database.SaveFileRequest(uploadRequest)
	uploadRequest, ok = filerequest.Get(uploadRequest.Id)
	if isNewRequest {
		logging.LogCreateFileRequest(uploadRequest, user)
	} else {
		logging.LogEditFileRequest(uploadRequest, user)
	}
	if request.IsClosedSet && request.Closed && !wasClosed {
		logging.LogCloseFileRequest(uploadRequest, user, false)
	}
	response := map[string]interface{}{
		"Result":      "OK",
		"FileRequest": uploadRequest,
	}
	result, err := json.Marshal(response)
	helper.Check(err)
	_, _ = w.Write(result)
}

// apiURequestComplete closes a file request from the public upload page, so whoever is sending
// the files can say they are done instead of leaving the request open until it expires or fills
// up. Anyone holding the link can do this - a file request link is a shared address rather than a
// personal identity, so there is no finer-grained actor to authorise against. The owner can
// reopen the request, which is what keeps this recoverable instead of destructive.
//
// Deliberately does not go through checkFileRequestAndApiKey: that refuses an expired or full
// request, and closing one of those is harmless and still the outcome the caller asked for.
func apiURequestComplete(w http.ResponseWriter, r requestParser, user models.User, apikey models.ApiKey) {
	request, ok := r.(*paramURequestComplete)
	if !ok {
		panic("invalid parameter passed")
	}
	uploadRequest, ok := database.GetFileRequest(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "FileRequest does not exist with the given ID")
		return
	}
	if uploadRequest.ApiKey != apikey.Id {
		sendError(w, http.StatusUnauthorized, errorcodes.InvalidApiKey, "Invalid API key")
		return
	}
	if !uploadRequest.Closed {
		uploadRequest.Closed = true
		uploadRequest.ClosedAt = time.Now().Unix()
		database.SaveFileRequest(uploadRequest)
		logging.LogCloseFileRequest(uploadRequest, user, true)
	}
	_, _ = w.Write([]byte(`{"Result":"OK"}`))
}

// closeFullFileRequest marks a request complete once it holds every file it may accept. A
// full request can take nothing more, so leaving it open would only hide from the owner that
// the upload is finished.
func closeFullFileRequest(fr models.FileRequest, user models.User) {
	stored, ok := database.GetFileRequest(fr.Id)
	if !ok || stored.Closed {
		return
	}
	stored.Closed = true
	stored.ClosedAt = time.Now().Unix()
	database.SaveFileRequest(stored)
	logging.LogFileRequestFull(stored, user)
}

func apiUploadRequestList(w http.ResponseWriter, _ requestParser, user models.User, _ models.ApiKey) {
	userRequests := make([]models.FileRequest, 0)
	users := userMap()
	for _, request := range filerequest.GetAll() {
		if mayViewFileRequest(request, user) {
			// request.Name is empty when it could not be decrypted (see models.FileRequest.Name),
			// which happens while the instance is sealed. Rendered as the placeholder rather than
			// left blank; Notes is left as-is, since an empty note is a normal value there.
			request.Name = request.DisplayName()
			fillFileRequestNames(&request, users)
			userRequests = append(userRequests, request)
		}
	}
	result, err := json.Marshal(userRequests)
	helper.Check(err)
	_, _ = w.Write(result)
}

func apiUploadRequestListSingle(w http.ResponseWriter, r requestParser, user models.User, _ models.ApiKey) {
	request, ok := r.(*paramURequestListSingle)
	if !ok {
		panic("invalid parameter passed")
	}

	uploadRequest, ok := filerequest.Get(request.Id)
	if !ok {
		sendError(w, http.StatusNotFound, errorcodes.NotFound, "FileRequest does not exist with the given ID")
		return
	}
	if !mayViewFileRequest(uploadRequest, user) {
		sendError(w, http.StatusUnauthorized, errorcodes.NoPermission, "No permission to show this upload request")
		return
	}
	uploadRequest.Name = uploadRequest.DisplayName()
	fillFileRequestNames(&uploadRequest, userMap())
	result, err := json.Marshal(uploadRequest)
	helper.Check(err)
	_, _ = w.Write(result)
}

func isAuthorisedForApi(r *http.Request, routing apiRoute) (models.User, models.ApiKey, bool) {
	keyId := r.Header.Get("apikey")
	ratelimiter.WaitOnApiAuthentication(logging.GetIpAddress(r))
	user, apiKey, ok := isValidApiKey(keyId, true, routing.ApiPerm)
	if !ok {
		return models.User{}, models.ApiKey{}, false
	}
	// Returns false if a public upload key is used for non-public api call or vice versa
	if routing.IsFileRequestApi != apiKey.IsUploadRequestKey() {
		return models.User{}, models.ApiKey{}, false
	}
	return user, apiKey, true
}

func sendError(w http.ResponseWriter, statusCode, errorCode int, errorMessage string) {
	if w == nil {
		return
	}
	w.WriteHeader(statusCode)
	output := struct {
		Result  string `json:"Result"`
		Message string `json:"ErrorMessage"`
		Code    int    `json:"ErrorCode"`
	}{Result: "error", Message: errorMessage, Code: errorCode}
	outputBytes, err := json.Marshal(output)
	helper.Check(err)
	_, _ = w.Write(outputBytes)
}

// publicKeyToApiKey tries to convert a (possible) public key to a private key
// If not a public key or if invalid, the original value is returned
func publicKeyToApiKey(publicKey string) string {
	if len(publicKey) == LengthPublicId {
		privateApiKey, ok := database.GetApiKeyByPublicKey(publicKey)
		if ok {
			return privateApiKey
		}
	}
	return publicKey
}

// isValidApiKey checks if the API key provides is valid. If modifyTime is true, it also automatically updates
// the lastUsed timestamp
func isValidApiKey(key string, modifyTime bool, requiredPermissionApiKey models.ApiPermission) (models.User, models.ApiKey, bool) {
	if key == "" {
		return models.User{}, models.ApiKey{}, false
	}
	savedKey, ok := database.GetApiKey(key)
	if ok && savedKey.Id != "" && (savedKey.Expiry == 0 || savedKey.Expiry > time.Now().Unix()) {
		if modifyTime {
			savedKey.LastUsed = time.Now().Unix()
			database.UpdateTimeApiKey(savedKey)
		}
		if !savedKey.HasPermission(requiredPermissionApiKey) {
			return models.User{}, models.ApiKey{}, false
		}
		user, ok := database.GetUser(savedKey.UserId)
		if !ok {
			return models.User{}, models.ApiKey{}, false
		}
		return user, savedKey, true
	}
	return models.User{}, models.ApiKey{}, false
}
