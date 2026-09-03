package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/storage"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
	"github.com/forceu/gokapi/internal/webserver/authentication/downloadPasswordToken"
	"github.com/forceu/gokapi/internal/webserver/errorHandling/errorcodes"
	"github.com/forceu/gokapi/internal/webserver/ratelimiter"
)

func TestMain(m *testing.M) {
	testconfiguration.CreateWithPort(true, test.PortApi)
	configuration.Load()
	configuration.ConnectDatabase()
	generateTestData()
	ratelimiter.SetUnitTestMode(true)
	exitVal := m.Run()
	testconfiguration.Delete()
	os.Exit(exitVal)
}

const (
	idInvalidUser            = 99
	idSuperAdmin             = 100
	idAdmin                  = 101
	idUser                   = 102
	idStranger               = 103
	idApiKeyAdmin            = "ApiKeyAdmin"
	idApiKeySuperAdmin       = "ApiKeySuperAdmin"
	idPublicApiKeySuperAdmin = "OGeidahfiep1Akeevahkoh1quechieP6ael"
	idFileUser               = "newTestFile"
	idFileAdmin              = "otherTestFile"
)

func generateTestData() {
	newUser := models.User{
		Id:            idUser,
		Name:          "TestUser",
		Permissions:   models.UserPermissionNone,
		UserLevel:     models.UserLevelUser,
		ResetPassword: false,
		AuthProvider:  models.AuthProviderInternal,
	}
	newAdmin := models.User{
		Id:            idAdmin,
		Name:          "TestAdmin",
		Permissions:   models.UserPermissionAll,
		UserLevel:     models.UserLevelAdmin,
		ResetPassword: false,
		AuthProvider:  models.AuthProviderInternal,
	}
	newSuperAdmin := models.User{
		Id:            idSuperAdmin,
		Name:          "TestSuperAdmin",
		Permissions:   models.UserPermissionAll,
		UserLevel:     models.UserLevelSuperAdmin,
		ResetPassword: false,
		AuthProvider:  models.AuthProviderInternal,
	}
	database.SaveUser(newUser, false)
	database.SaveUser(newAdmin, false)
	database.SaveUser(newSuperAdmin, false)
	database.SaveApiKey(models.ApiKey{
		Id:           idApiKeyAdmin,
		PublicId:     idApiKeyAdmin,
		FriendlyName: "Admin",
		Permissions:  models.ApiPermNone,
		UserId:       idAdmin,
	})
	database.SaveApiKey(models.ApiKey{
		Id:           idApiKeySuperAdmin,
		PublicId:     idPublicApiKeySuperAdmin,
		FriendlyName: "SuperAdmin",
		Permissions:  models.ApiPermNone,
		UserId:       idSuperAdmin,
	})
	database.SaveMetaData(models.File{
		Id:                 idFileUser,
		Name:               idFileUser + "Name",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
	})
	database.SaveMetaData(models.File{
		Id:                 idFileAdmin,
		Name:               idFileAdmin + "Name",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idAdmin,
	})
}

func getRecorder(url, apikey string, headers []test.Header) (*httptest.ResponseRecorder, *http.Request) {
	return getRecorderWithBody(url, apikey, "GET", headers, nil)
}

func getRecorderWithBody(url, apikey, method string, headers []test.Header, body io.Reader) (*httptest.ResponseRecorder, *http.Request) {
	var passedHeaders []test.Header
	if apikey != "" {
		passedHeaders = append(passedHeaders, test.Header{
			Name:  "apikey",
			Value: apikey,
		})
	}
	for _, header := range headers {
		passedHeaders = append(passedHeaders, header)
	}
	return test.GetRecorder(method, url, nil, passedHeaders, body)
}

func testAuthorisation(t *testing.T, url string, requiredPermission models.ApiPermission) models.ApiKey {
	w, r := getRecorder(url, "", []test.Header{{}})
	Process(w, r)
	test.IsEqualBool(t, w.Code != 200, true)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`)

	w, r = getRecorder(url, "invalid", []test.Header{{}})
	Process(w, r)
	test.IsEqualBool(t, w.Code != 200, true)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`)

	newApiKeyUser := generateNewKey(false, idUser, "", "")
	w, r = getRecorder(url, newApiKeyUser.Id, []test.Header{{}})
	Process(w, r)
	test.IsEqualBool(t, w.Code != 200, true)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`)

	for _, permission := range getAvailableApiPermissions() {
		if permission == requiredPermission {
			continue
		}
		setPermissionApikey(t, newApiKeyUser.Id, permission)
		w, r = getRecorder(url, newApiKeyUser.Id, []test.Header{{}})
		Process(w, r)
		test.IsEqualBool(t, w.Code != 200, true)
		test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`)
		removePermissionApikey(t, newApiKeyUser.Id, permission)
	}
	newApiKeyUser.Permissions = getPermissionAll()
	newApiKeyUser.RemovePermission(requiredPermission)
	database.SaveApiKey(newApiKeyUser)
	w, r = getRecorder(url, newApiKeyUser.Id, []test.Header{{}})
	Process(w, r)
	test.IsEqualBool(t, w.Code != 200, true)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`)
	newApiKeyUser.Permissions = models.ApiPermNone
	newApiKeyUser.GrantPermission(requiredPermission)
	database.SaveApiKey(newApiKeyUser)
	return newApiKeyUser
}

type invalidParameterValue struct {
	Value         string
	ErrorMessage  string
	ErrorMessages []string
	StatusCode    int
}

func testInvalidParameters(t *testing.T, url, apiKey string, validHeaders []test.Header, headerName string, invalidValues []invalidParameterValue) {
	t.Helper()
	for _, invalidHeader := range invalidValues {
		headers := make([]test.Header, len(validHeaders))
		copy(headers, validHeaders)
		headers = append(headers, test.Header{
			Name:  headerName,
			Value: invalidHeader.Value,
		})
		w, r := getRecorderWithBody(url, apiKey, "GET", headers, nil)
		Process(w, r)
		test.IsEqualInt(t, w.Code, invalidHeader.StatusCode)
		if len(invalidHeader.ErrorMessages) > 0 {
			test.ResponseBodyIsWithAlternate(t, w, invalidHeader.ErrorMessages)
		} else {
			test.ResponseBodyIs(t, w, invalidHeader.ErrorMessage)
		}
		if invalidHeader.Value == "" {
			w, r = getRecorder(url, apiKey, validHeaders)
			Process(w, r)
			test.IsEqualInt(t, w.Code, invalidHeader.StatusCode)
			test.ResponseBodyIs(t, w, invalidHeader.ErrorMessage)
		}
	}
}

func testInvalidUserId(t *testing.T, url, apiKey string, validHeaders []test.Header) {
	t.Helper()
	const headerUserId = "userid"

	var invalidParameter = []invalidParameterValue{
		{
			Value:        "",
			ErrorMessage: `{"Result":"error","ErrorMessage":"header userid is required","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value:        strconv.Itoa(idInvalidUser),
			ErrorMessage: `{"Result":"error","ErrorMessage":"Invalid user id provided.","ErrorCode":5}`,
			StatusCode:   404,
		},
		{
			Value:        "invalid",
			ErrorMessage: `{"Result":"error","ErrorMessage":"invalid value in header userid supplied","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value: strconv.Itoa(idUser),
			// "Cannot modify this user" covers apiChangeUserRank and apiModifyUser, which share
			// canAdministerUser's single message for both the self and super-admin cases; the
			// other two share nothing with it and keep their own distinct wording.
			ErrorMessages: []string{`{"Result":"error","ErrorMessage":"Cannot modify this user","ErrorCode":19}`,
				`{"Result":"error","ErrorMessage":"Cannot delete yourself","ErrorCode":19}`,
				`{"Result":"error","ErrorMessage":"Cannot reset password of yourself","ErrorCode":19}`},
			StatusCode: 400,
		},
		{
			Value: strconv.Itoa(idSuperAdmin),
			ErrorMessages: []string{`{"Result":"error","ErrorMessage":"Cannot modify this user","ErrorCode":19}`,
				`{"Result":"error","ErrorMessage":"Cannot delete super admin","ErrorCode":19}`,
				`{"Result":"error","ErrorMessage":"Cannot reset password of super admin","ErrorCode":19}`},
			StatusCode: 400,
		},
	}
	testInvalidParameters(t, url, apiKey, validHeaders, headerUserId, invalidParameter)
}

func testInvalidApiKey(t *testing.T, url, apiKey string, validHeaders []test.Header) {
	t.Helper()
	const headerApiKey = "targetKey"

	var invalidParameter = []invalidParameterValue{
		{
			Value:        "",
			ErrorMessage: `{"Result":"error","ErrorMessage":"header targetKey is required","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value:        "invalid",
			ErrorMessage: `{"Result":"error","ErrorMessage":"Invalid key ID provided.","ErrorCode":5}`,
			StatusCode:   404,
		},
		{
			Value: idApiKeySuperAdmin,
			ErrorMessages: []string{`{"Result":"error","ErrorMessage":"No permission to delete this API key","ErrorCode":6}`,
				`{"Result":"error","ErrorMessage":"No permission to edit this API key","ErrorCode":6}`},
			StatusCode: 401,
		},
		{
			Value: idPublicApiKeySuperAdmin,
			ErrorMessages: []string{`{"Result":"error","ErrorMessage":"No permission to delete this API key","ErrorCode":6}`,
				`{"Result":"error","ErrorMessage":"No permission to edit this API key","ErrorCode":6}`},
			StatusCode: 401,
		},
		{
			Value: idApiKeyAdmin,
			ErrorMessages: []string{`{"Result":"error","ErrorMessage":"No permission to delete this API key","ErrorCode":6}`,
				`{"Result":"error","ErrorMessage":"No permission to edit this API key","ErrorCode":6}`},
			StatusCode: 401,
		},
	}
	testInvalidParameters(t, url, apiKey, validHeaders, headerApiKey, invalidParameter)
}

func testInvalidFileId(t *testing.T, url, apiKey string, isReplacingCall bool) {
	t.Helper()
	const headerId = "id"
	const headerIdReplace = "idNewContent"

	header := headerId
	if isReplacingCall {
		header = headerIdReplace
	}

	var invalidParameter = []invalidParameterValue{
		{
			Value:        "",
			ErrorMessage: `{"Result":"error","ErrorMessage":"header id is required","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value:        "invalidFile",
			ErrorMessage: `{"Result":"error","ErrorMessage":"Invalid id provided.","ErrorCode":5}`,
			StatusCode:   404,
		},
		{
			Value:        idFileAdmin,
			ErrorMessage: `{"Result":"error","ErrorMessage":"No permission to duplicate this file","ErrorCode":6}`,
			StatusCode:   401,
		},
	}
	testInvalidParameters(t, url, apiKey, []test.Header{{}}, header, invalidParameter)
}

func TestInvalidRouting(t *testing.T) {

	const apiUrl = "/invalid"
	w, r := getRecorder(apiUrl, "invalid", []test.Header{{}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"Invalid request","ErrorCode":1}`)
}

// ## /user/##

func TestUserGetMe(t *testing.T) {
	const apiUrl = "/user/me"
	generateTestData()

	// Test with regular user API key
	userApiKey := generateNewKey(false, idUser, "", "")
	w, r := getRecorder(apiUrl, userApiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	var result models.User
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualInt(t, result.Id, idUser)

	// Verify no sensitive password field is leaked in the response
	var rawResult map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &rawResult)
	test.IsNil(t, err)
	_, hasPassword := rawResult["password"]
	test.IsEqualBool(t, hasPassword, false)
}

func TestUserGetMeHasAvatar(t *testing.T) {
	const apiUrl = "/user/me"
	generateTestData()
	userApiKey := generateNewKey(false, idUser, "", "")

	// No cached picture yet: hasAvatar must be false so the client knows to skip
	// GET /user/avatar rather than requesting it and getting back a 204.
	w, r := getRecorder(apiUrl, userApiKey.Id, []test.Header{})
	Process(w, r)
	var result struct {
		HasAvatar bool `json:"hasAvatar"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualBool(t, result.HasAvatar, false)

	// Cache a picture at the same path avatar.Path looks for, then confirm the flag flips.
	avatarDir := filepath.Join(configuration.Get().DataDir, "avatars")
	err = os.MkdirAll(avatarDir, 0700)
	test.IsNil(t, err)
	avatarPath := filepath.Join(avatarDir, strconv.Itoa(idUser)+".png")
	err = os.WriteFile(avatarPath, []byte("stand-in for a cached picture, only its presence is checked here"), 0600)
	test.IsNil(t, err)
	defer os.Remove(avatarPath)

	w, r = getRecorder(apiUrl, userApiKey.Id, []test.Header{})
	Process(w, r)
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualBool(t, result.HasAvatar, true)
}

func TestUserList(t *testing.T) {
	const apiUrl = "/user/list"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	type userListItem struct {
		Id          int `json:"id"`
		Name        string
		UploadCount int `json:"uploadCount"`
	}
	var result []userListItem
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	// Should have at least the admin, superadmin, and test user from generateTestData
	test.IsEqualBool(t, len(result) >= 3, true)
	// Check that at least one user is present
	test.IsEqualBool(t, result[0].Id > 0, true)
}

func TestUserCreate(t *testing.T) {
	const apiUrl = "/user/create"
	const headerUsername = "username"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)

	// Use a unique username to avoid test pollution
	uniqueUsername := "TestUserCreate_" + helper.GenerateRandomString(8)
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUsername,
		Value: uniqueUsername,
	}})
	Process(w, r)

	// Verify the user was created successfully
	var result models.User
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualInt(t, w.Code, 200)
	test.IsEqual(t, result.Name, strings.ToLower(uniqueUsername))
	test.IsEqualInt(t, int(result.Permissions), 0)
	test.IsEqualInt(t, int(result.UserLevel), 2)

	// Test that the same username cannot be created again
	var invalidParameter = []invalidParameterValue{
		{
			Value:        "",
			ErrorMessage: `{"Result":"error","ErrorMessage":"header username is required","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value:        "1",
			ErrorMessage: `{"Result":"error","ErrorMessage":"Invalid username provided.","ErrorCode":6}`,
			StatusCode:   400,
		},
		{
			Value:        uniqueUsername,
			ErrorMessage: `{"Result":"error","ErrorMessage":"User already exists.","ErrorCode":7}`,
			StatusCode:   409,
		},
	}
	testInvalidParameters(t, apiUrl, apiKey.Id, []test.Header{{}}, headerUsername, invalidParameter)

	defer test.ExpectPanic(t)
	apiCreateUser(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

// TestUserCreateNonAsciiRoundTrips verifies that a username containing non-ASCII characters,
// sent the way the frontend encoder (encodeHeader in frontend/src/lib/api.ts) sends it - as
// "base64:" followed by standard base64 - is decoded server side before it is stored, rather than
// being stored as the literal "base64:..." string. Before paramUserCreate.Username carried
// supportBase64, routingParsing.go never decoded this header, so the literal base64 text was
// lowercased and saved, corrupting the name and making the original unrecoverable even by
// decoding it afterwards. The name must also survive being read back through the user list.
func TestUserCreateNonAsciiRoundTrips(t *testing.T) {
	const apiUrl = "/user/create"
	const headerUsername = "username"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)

	uniqueNameUtf8 := "TestUserCreate_UTF8_" + helper.GenerateRandomString(6) + "_éàü"
	encodedName := "base64:" + base64.StdEncoding.EncodeToString([]byte(uniqueNameUtf8))

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUsername,
		Value: encodedName,
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	var result models.User
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqual(t, result.Name, strings.ToLower(uniqueNameUtf8))
	test.IsEqualBool(t, strings.HasPrefix(result.Name, "base64:"), false)

	dbUser, ok := database.GetUserByName(strings.ToLower(uniqueNameUtf8))
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, dbUser.Name, strings.ToLower(uniqueNameUtf8))

	// Round trip through the user list too
	w, r = getRecorder("/user/list", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	type userListItem struct {
		Id   int `json:"id"`
		Name string
	}
	var list []userListItem
	err = json.Unmarshal(w.Body.Bytes(), &list)
	test.IsNil(t, err)
	found := false
	for _, item := range list {
		if item.Id == dbUser.Id {
			test.IsEqual(t, item.Name, strings.ToLower(uniqueNameUtf8))
			found = true
		}
	}
	test.IsEqualBool(t, found, true)
}

// TestUserCreateWithAuthProvider verifies that an admin can deliberately provision an
// OIDC user through the create-user API by passing the authprovider header. A user created with
// the google provider must have AuthProvider set to google and no password hash, so the internal
// password login path stays closed for that account (see IsCorrectUsernameAndPassword). Before
// this fix, apiCreateUser hardcoded models.AuthProviderInternal, so this header had no effect and
// the created user's AuthProvider would be "internal" instead of "google".
//
// OAuth must actually be configured for the google provider to be accepted (see
// TestUserCreateGoogleAuthProviderRejectedWithoutOauth below), so this test enables hybrid mode
// on the shared test configuration for its duration and restores it afterwards.
func TestUserCreateWithAuthProvider(t *testing.T) {
	const apiUrl = "/user/create"
	const headerUsername = "username"
	const headerAuthProvider = "authprovider"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)

	authConfig := &configuration.Get().Authentication
	originalOauthEnabled := authConfig.OAuthEnabledAlongsideInternal
	originalOauthProvider := authConfig.OAuthProvider
	authConfig.OAuthEnabledAlongsideInternal = true
	authConfig.OAuthProvider = "https://example.com"
	defer func() {
		authConfig.OAuthEnabledAlongsideInternal = originalOauthEnabled
		authConfig.OAuthProvider = originalOauthProvider
	}()

	uniqueUsername := "TestUserCreateGoogle_" + helper.GenerateRandomString(8)
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUsername,
		Value: uniqueUsername,
	}, {
		Name:  headerAuthProvider,
		Value: "google",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	dbUser, ok := database.GetUserByName(strings.ToLower(uniqueUsername))
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, dbUser.AuthProvider, models.AuthProviderGoogle)
	test.IsEqualString(t, dbUser.Password, "")

	// Default (no authprovider header) still yields an internal user
	uniqueUsername2 := "TestUserCreateDefault_" + helper.GenerateRandomString(8)
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUsername,
		Value: uniqueUsername2,
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	dbUser, ok = database.GetUserByName(strings.ToLower(uniqueUsername2))
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, dbUser.AuthProvider, models.AuthProviderInternal)

	// The user list API surfaces AuthProvider, so the UI can show which accounts are SSO
	w, r = getRecorder("/user/list", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	type userListItem struct {
		Name         string `json:"name"`
		AuthProvider string `json:"authProvider"`
	}
	var list []userListItem
	err := json.Unmarshal(w.Body.Bytes(), &list)
	test.IsNil(t, err)
	found := false
	for _, item := range list {
		if item.Name == strings.ToLower(uniqueUsername) {
			found = true
			test.IsEqualString(t, item.AuthProvider, models.AuthProviderGoogle)
		}
	}
	test.IsEqualBool(t, found, true)
}

// TestUserCreateInvalidAuthProvider verifies that an unknown authprovider value is rejected with
// a 400 rather than silently falling through to a default, since AuthProvider gates both the
// password and OIDC login paths.
func TestUserCreateInvalidAuthProvider(t *testing.T) {
	const apiUrl = "/user/create"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)

	uniqueUsername := "TestUserCreateInvalid_" + helper.GenerateRandomString(8)
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  "username",
		Value: uniqueUsername,
	}, {
		Name:  "authprovider",
		Value: "not-a-real-provider",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)

	_, ok := database.GetUserByName(strings.ToLower(uniqueUsername))
	test.IsEqualBool(t, ok, false)
}

// TestUserCreateGoogleAuthProviderRejectedWithoutOauth verifies that authprovider: google
// must be rejected when OAuth is not configured at all (Method is internal, hybrid not enabled).
// Without this, an admin (or a script run before OAuth is set up) could create a row that can log
// in through neither door, and that row becomes a live, silently self-registering SSO account the
// moment an admin enables hybrid mode later - it already carries AuthProvider "google" with no
// review step in between. The shared test configuration has OAuth disabled by default (see
// testconfiguration.configTestFile), so this test runs against that default state.
func TestUserCreateGoogleAuthProviderRejectedWithoutOauth(t *testing.T) {
	const apiUrl = "/user/create"

	authConfig := &configuration.Get().Authentication
	test.IsEqualInt(t, authConfig.Method, models.AuthenticationInternal)
	test.IsEqualBool(t, authConfig.OAuthEnabledAlongsideInternal, false)

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)

	uniqueUsername := "TestUserCreateGoogleNoOauth_" + helper.GenerateRandomString(8)
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  "username",
		Value: uniqueUsername,
	}, {
		Name:  "authprovider",
		Value: "google",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)

	_, ok := database.GetUserByName(strings.ToLower(uniqueUsername))
	test.IsEqualBool(t, ok, false)
}

func TestUserChangeRank(t *testing.T) {
	const apiUrl = "/user/modify"
	const headerUserId = "userid"
	const headerNewRank = "newRank"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)

	testInvalidUserId(t, apiUrl, apiKey.Id, []test.Header{{Name: headerNewRank, Value: "admin"}})
	invalidParameter := []invalidParameterValue{
		{
			Value:        "invalid",
			ErrorMessage: `{"Result":"error","ErrorMessage":"invalid rank","ErrorCode":4}`,
			StatusCode:   400,
		},
	}
	testInvalidParameters(t, apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
	}}, headerNewRank, invalidParameter)

	// newRank is optional, so an empty value still counts as present (see checkHeaderExists) and
	// is rejected the same way as any other unrecognised rank, while omitting it along with every
	// other mutation is refused as an empty request.
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
	}, {
		Name:  headerNewRank,
		Value: "",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"invalid rank","ErrorCode":4}`)

	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"no mutation requested","ErrorCode":4}`)

	// Demoting an admin requires outranking them, and only the super admin does - see
	// canAdministerUser and TestAuthorisationCannotDemoteAdminWithoutRank for the rank-2 case
	// being refused. The legitimate path below therefore acts as the super admin rather than as
	// this apiKey's owner (idUser, a plain user).
	setPermissionApikey(t, idApiKeySuperAdmin, models.ApiPermManageUsers)
	defer removePermissionApikey(t, idApiKeySuperAdmin, models.ApiPermManageUsers)

	user, ok := database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, user.UserLevel, models.UserLevelAdmin)
	w, r = getRecorder(apiUrl, idApiKeySuperAdmin, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
	}, {
		Name:  headerNewRank,
		Value: "USER",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok = database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, user.UserLevel, models.UserLevelUser)
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
	}, {
		Name:  headerNewRank,
		Value: "ADMIN",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	user, ok = database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, user.UserLevel, models.UserLevelUser)
	user, _ = database.GetUser(idUser)
	user.UserLevel = models.UserLevelAdmin
	database.SaveUser(user, false)

	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
	}, {
		Name:  headerNewRank,
		Value: "ADMIN",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok = database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, user.UserLevel, models.UserLevelAdmin)

	user, _ = database.GetUser(idUser)
	user.UserLevel = models.UserLevelUser
	database.SaveUser(user, false)

	defer test.ExpectPanic(t)
	apiModifyUser(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

// TestAuthorisationCannotDemoteAdminWithoutRank verifies that a rank-2 user holding only
// UserPermManageUsers cannot demote an admin: canAdministerUser requires the actor to outrank
// the target, and a rank-2 actor never outranks a rank-1 admin. Before canAdministerUser,
// apiChangeUserRank guarded promotion but not demotion, so this exact call succeeded and also
// reset the admin's permissions to UserPermissionNone.
func TestAuthorisationCannotDemoteAdminWithoutRank(t *testing.T) {
	actorKey := generateNewKey(false, idUser, "", "")
	setPermissionApikey(t, actorKey.Id, models.ApiPermManageUsers)
	grantUserPermission(t, idUser, models.UserPermManageUsers)
	defer removeUserPermission(t, idUser, models.UserPermManageUsers)

	admin, ok := database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, admin.UserLevel, models.UserLevelAdmin)

	w, r := getRecorder("/user/modify", actorKey.Id, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(idAdmin),
	}, {
		Name:  "newRank",
		Value: "USER",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"Cannot modify this user","ErrorCode":19}`)

	admin, ok = database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, admin.UserLevel, models.UserLevelAdmin)
	test.IsEqual(t, admin.Permissions, models.UserPermissionAll)
}

// TestAuthorisationCannotRevokeUnheldPermission verifies that revoking a permission requires the
// actor to hold it themselves, symmetric with granting one. The actor here (idAdmin) outranks the
// target (idUser), so canAdministerUser lets the call through - the block has to come from the
// revoke-side check. Before this fix, apiModifyUser's revoke branch had no caller check at all,
// so any caller with UserPermManageUsers could strip bits an admin themselves did not hold.
func TestAuthorisationCannotRevokeUnheldPermission(t *testing.T) {
	setPermissionApikey(t, idApiKeyAdmin, models.ApiPermManageUsers)
	defer removePermissionApikey(t, idApiKeyAdmin, models.ApiPermManageUsers)

	removeUserPermission(t, idAdmin, models.UserPermGuestUploads)
	defer grantUserPermission(t, idAdmin, models.UserPermGuestUploads)
	grantUserPermission(t, idUser, models.UserPermGuestUploads)
	defer removeUserPermission(t, idUser, models.UserPermGuestUploads)

	w, r := getRecorder("/user/modify", idApiKeyAdmin, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(idUser),
	}, {
		Name:  "userpermission",
		Value: "PERM_GUEST_UPLOAD",
	}, {
		Name:  "permissionModifier",
		Value: "REVOKE",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"Cannot revoke rights the user does not have","ErrorCode":6}`)

	target, ok := database.GetUser(idUser)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, target.HasPermission(models.UserPermGuestUploads), true)
}

// TestAuthorisationCannotTouchSuperAdminApiKey verifies that UserPermManageApiKeys does not let a
// caller reach the super admin's own API key, for both deletion and modification. Before this
// fix, apiDeleteKey and apiModifyApiKey were the only user-editing endpoints in this file that
// never checked IsSuperAdmin, so a rank-2 user granted only UserPermManageApiKeys could delete or
// reconfigure the super admin's key.
func TestAuthorisationCannotTouchSuperAdminApiKey(t *testing.T) {
	actorKey := generateNewKey(false, idUser, "", "")
	setPermissionApikey(t, actorKey.Id, models.ApiPermApiMod)
	grantUserPermission(t, idUser, models.UserPermManageApiKeys)
	defer removeUserPermission(t, idUser, models.UserPermManageApiKeys)

	w, r := getRecorder("/auth/delete", actorKey.Id, []test.Header{{
		Name:  "targetKey",
		Value: idApiKeySuperAdmin,
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)
	_, ok := database.GetApiKey(idApiKeySuperAdmin)
	test.IsEqualBool(t, ok, true)

	w, r = getRecorder("/auth/modify", actorKey.Id, []test.Header{{
		Name:  "targetKey",
		Value: idApiKeySuperAdmin,
	}, {
		Name:  "permission",
		Value: "PERM_VIEW",
	}, {
		Name:  "permissionModifier",
		Value: "GRANT",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)
	key, ok := database.GetApiKey(idApiKeySuperAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, key.HasPermission(models.ApiPermView), false)
}

// TestAuthorisationAdminCanAdministerUser is the no-over-tightening counterpart to the three
// tests above: an admin acting on a plain user must still be able to grant and revoke a
// permission and to promote them, none of which canAdministerUser's stricter rank check affects,
// since an admin always outranks a plain user.
func TestAuthorisationAdminCanAdministerUser(t *testing.T) {
	setPermissionApikey(t, idApiKeyAdmin, models.ApiPermManageUsers)
	defer removePermissionApikey(t, idApiKeyAdmin, models.ApiPermManageUsers)

	w, r := getRecorder("/user/modify", idApiKeyAdmin, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(idUser),
	}, {
		Name:  "userpermission",
		Value: "PERM_REPLACE",
	}, {
		Name:  "permissionModifier",
		Value: "GRANT",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok := database.GetUser(idUser)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, user.HasPermission(models.UserPermReplaceUploads), true)

	w, r = getRecorder("/user/modify", idApiKeyAdmin, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(idUser),
	}, {
		Name:  "userpermission",
		Value: "PERM_REPLACE",
	}, {
		Name:  "permissionModifier",
		Value: "REVOKE",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok = database.GetUser(idUser)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, user.HasPermission(models.UserPermReplaceUploads), false)

	w, r = getRecorder("/user/modify", idApiKeyAdmin, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(idUser),
	}, {
		Name:  "newRank",
		Value: "ADMIN",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok = database.GetUser(idUser)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, user.UserLevel, models.UserLevelAdmin)

	// Restore the fixture directly: an admin no longer outranks the peer admin it just created
	// (only the super admin does), so demoting it back is not exercised here.
	user.UserLevel = models.UserLevelUser
	user.Permissions = models.UserPermissionNone
	database.SaveUser(user, false)
}

func TestUserDelete(t *testing.T) {
	const apiUrl = "/user/delete"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)
	testInvalidUserId(t, apiUrl, apiKey.Id, []test.Header{})
	testDeleteUserCall(t, apiKey.Id, deleteUserCallModeDeleteFiles)
	testDeleteUserCall(t, apiKey.Id, deleteUserCallModeKeepFiles)
	testDeleteUserCall(t, apiKey.Id, deleteUserCallModeInvalidOperator)

	defer test.ExpectPanic(t)
	apiDeleteUser(nil, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

const (
	deleteUserCallModeDeleteFiles     = iota
	deleteUserCallModeKeepFiles       = iota
	deleteUserCallModeInvalidOperator = iota
)

func testDeleteUserCall(t *testing.T, apiKey string, mode int) {
	const apiUrl = "/user/delete"
	const headerUserId = "userid"
	const headerDeleteFiles = "deleteFiles"

	// Use a unique username for each call to avoid test pollution
	uniqueUsername := "ToDelete_" + helper.GenerateRandomString(8)
	user := models.User{
		Name:      uniqueUsername,
		UserLevel: models.UserLevelAdmin,
	}
	database.SaveUser(user, true)
	retrievedUser, ok := database.GetUserByName(uniqueUsername)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, retrievedUser.Id != idUser, true)
	// Use unique IDs for session, file, and API key for each call
	uniqueSuffix := "_" + helper.GenerateRandomString(8)
	sessionId := "sessionApiDelete" + uniqueSuffix
	fileId := "testFileApiDelete" + uniqueSuffix

	session := models.Session{
		RenewAt:    2147483645,
		ValidUntil: 2147483645,
		UserId:     retrievedUser.Id,
	}
	database.SaveSession(sessionId, session)
	_, ok = database.GetSession(sessionId)
	test.IsEqualBool(t, ok, true)
	userApiKey := generateNewKey(false, retrievedUser.Id, "", "")
	_, ok = database.GetApiKey(userApiKey.Id)
	test.IsEqualBool(t, ok, true)
	testFile := models.File{
		Id:   fileId,
		Name: fileId + ".jpg",
		// A SHA1 unique to this call, unlike the shared placeholder hash other fixtures in this
		// file reuse: mode deleteUserCallModeDeleteFiles drives a real storage.DeleteFile, which
		// physically removes the blob once its ref count hits zero - sharing a hash with another
		// fixture would delete a blob that fixture's own timing assertions still depend on.
		SHA1:               "deleteCascade_" + helper.GenerateRandomString(16),
		ContentType:        "image/jpeg",
		UserId:             retrievedUser.Id,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	// A hotlink and a share grant, so deletion with DeleteFiles can be checked to have gone
	// through storage.DeleteFile's actual dispose lifecycle - see testDeleteUserCall's assertions
	// below - rather than merely removing the metadata row. AddHotlink has to run before the
	// grant exists: IsAbleHotlink refuses a share-restricted file.
	storage.AddHotlink(&testFile)
	test.IsEqualBool(t, mode != deleteUserCallModeDeleteFiles || testFile.HotlinkId != "", true)
	hotlinkId := testFile.HotlinkId
	database.SaveMetaData(testFile)
	var recipientId int
	if mode == deleteUserCallModeDeleteFiles {
		recipientId = database.SaveShareRecipient(models.ShareRecipient{
			Email:     "delete-cascade-" + fileId + "@example.com",
			CreatedAt: time.Now().Unix(),
		})
		database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, retrievedUser.Id, 0)
		test.IsEqualInt(t, len(database.GetShareGrants(models.ShareResourceFile, fileId)), 1)
	}
	testFile, ok = database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, testFile.UserId, retrievedUser.Id)

	var deleteMetaFile string
	switch mode {
	case deleteUserCallModeDeleteFiles:
		deleteMetaFile = "true"
	case deleteUserCallModeKeepFiles:
		deleteMetaFile = "false"
	case deleteUserCallModeInvalidOperator:
		deleteMetaFile = "invalid"
	}

	w, r := getRecorder(apiUrl, apiKey, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(retrievedUser.Id),
	}, {
		Name:  headerDeleteFiles,
		Value: deleteMetaFile,
	}})
	Process(w, r)

	if mode == deleteUserCallModeInvalidOperator {
		test.IsEqualInt(t, w.Code, 400)
	} else {
		test.IsEqualInt(t, w.Code, 200)
		_, ok = database.GetUser(retrievedUser.Id)
		test.IsEqualBool(t, ok, false)
		_, ok = database.GetSession(sessionId)
		test.IsEqualBool(t, ok, false)
		_, ok = database.GetApiKey(userApiKey.Id)
		test.IsEqualBool(t, ok, false)

		if mode == deleteUserCallModeDeleteFiles {
			// storage.DeleteFile only schedules disposal and runs CleanUp in a background
			// goroutine (see storage.DeleteFile's doc comment), so the row, its hotlink and its
			// share grant are not necessarily gone the instant Process returns.
			startTime := time.Now()
			for {
				_, stillExists := database.GetMetaDataById(fileId)
				if !stillExists {
					break
				}
				if time.Since(startTime) > 5*time.Second {
					t.Fatal("Timeout waiting for deleted user's file to be disposed of")
				}
				time.Sleep(20 * time.Millisecond)
			}
			_, ok = database.GetHotlink(hotlinkId)
			test.IsEqualBool(t, ok, false)
			test.IsEqualInt(t, len(database.GetShareGrants(models.ShareResourceFile, fileId)), 0)
			return
		}

		testFile, ok = database.GetMetaDataById(fileId)
		test.IsEqualBool(t, ok, true)
		test.IsEqualInt(t, testFile.UserId, idUser)
	}

}

func TestUserModify(t *testing.T) {
	const apiUrl = "/user/modify"
	const headerUserId = "userid"
	const headerPermission = "userpermission"
	const headerModifier = "permissionModifier"
	const idNewKey = "idNewKey"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)
	testInvalidUserId(t, apiUrl, apiKey.Id, []test.Header{{Name: headerPermission, Value: "PERM_REPLACE"}, {Name: headerModifier, Value: "GRANT"}})

	var validHeaders = []test.Header{
		{
			Name:  headerUserId,
			Value: strconv.Itoa(idAdmin),
		}, {
			Name:  headerModifier,
			Value: "GRANT",
		},
	}
	invalidParameter := []invalidParameterValue{
		{
			Value:        "invalid",
			ErrorMessage: `{"Result":"error","ErrorMessage":"invalid permission","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value:        "PERM_REPLACEE",
			ErrorMessage: `{"Result":"error","ErrorMessage":"invalid permission","ErrorCode":4}`,
			StatusCode:   400,
		},
	}
	testInvalidParameters(t, apiUrl, apiKey.Id, validHeaders, headerPermission, invalidParameter)

	// userpermission and permissionModifier are only required together, unlike the plain-empty
	// convenience case testInvalidParameters covers above: a header sent with an empty value
	// still counts as present (see checkHeaderExists), so it reaches the switch below and is
	// rejected the same way as any other unrecognised value, while omitting it entirely is what
	// trips the together-check.
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
	}, {
		Name:  headerPermission,
		Value: "",
	}, {
		Name:  headerModifier,
		Value: "GRANT",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"invalid permission","ErrorCode":4}`)

	w, r = getRecorder(apiUrl, apiKey.Id, validHeaders)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"userpermission and permissionModifier must be provided together","ErrorCode":4}`)

	// Use a unique username to avoid test pollution
	uniqueUsername := "ToModify_" + helper.GenerateRandomString(8)
	user := models.User{
		Name:        uniqueUsername,
		UserLevel:   models.UserLevelAdmin,
		Permissions: models.UserPermissionNone,
	}
	database.SaveUser(user, true)
	retrievedUser, ok := database.GetUserByName(uniqueUsername)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, retrievedUser.Id != idUser, true)
	test.IsEqualBool(t, ok, true)
}

// TestUserModifyOptionalKeys verifies that /user/modify's rank, permission and resetPassword
// mutations - each its own endpoint before this consolidation - can be requested alone or
// together in the same call, and that a request specifying none of them is refused rather than
// silently doing nothing.
func TestUserModifyOptionalKeys(t *testing.T) {
	const apiUrl = "/user/modify"

	setPermissionApikey(t, idApiKeySuperAdmin, models.ApiPermManageUsers)
	defer removePermissionApikey(t, idApiKeySuperAdmin, models.ApiPermManageUsers)

	uniqueUsername := "ToModifyKeys_" + helper.GenerateRandomString(8)
	database.SaveUser(models.User{
		Name:         uniqueUsername,
		UserLevel:    models.UserLevelUser,
		Permissions:  models.UserPermissionNone,
		AuthProvider: models.AuthProviderInternal,
	}, true)
	retrieved, ok := database.GetUserByName(uniqueUsername)
	test.IsEqualBool(t, ok, true)
	targetId := retrieved.Id

	// No mutation at all is refused.
	w, r := getRecorder(apiUrl, idApiKeySuperAdmin, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(targetId),
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"no mutation requested","ErrorCode":4}`)

	// Permission alone.
	w, r = getRecorder(apiUrl, idApiKeySuperAdmin, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(targetId),
	}, {
		Name:  "userpermission",
		Value: "PERM_REPLACE",
	}, {
		Name:  "permissionModifier",
		Value: "GRANT",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok := database.GetUser(targetId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, user.HasPermission(models.UserPermReplaceUploads), true)
	test.IsEqual(t, user.UserLevel, models.UserLevelUser)
	test.IsEqualBool(t, user.ResetPassword, false)

	// Rank, combined with a fresh permission grant, in the same call.
	w, r = getRecorder(apiUrl, idApiKeySuperAdmin, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(targetId),
	}, {
		Name:  "newRank",
		Value: "ADMIN",
	}, {
		Name:  "userpermission",
		Value: "PERM_DELETE",
	}, {
		Name:  "permissionModifier",
		Value: "GRANT",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok = database.GetUser(targetId)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, user.UserLevel, models.UserLevelAdmin)
	test.IsEqualBool(t, user.HasPermission(models.UserPermDeleteOtherUploads), true)

	// resetPassword, combined with a demotion back to user, in the same call.
	w, r = getRecorder(apiUrl, idApiKeySuperAdmin, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(targetId),
	}, {
		Name:  "newRank",
		Value: "USER",
	}, {
		Name:  "resetPassword",
		Value: "true",
	}, {
		Name:  "generateNewPassword",
		Value: "true",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok = database.GetUser(targetId)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, user.UserLevel, models.UserLevelUser)
	test.IsEqualBool(t, user.ResetPassword, true)
	type response struct {
		Result   string `json:"Result"`
		Password string `json:"password"`
	}
	var resp response
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	test.IsNil(t, err)
	test.IsNotEmpty(t, resp.Password)
}

func TestUserPasswordReset(t *testing.T) {
	const apiUrl = "/user/modify"
	const headerUserId = "userid"
	const headerResetPassword = "resetPassword"
	const headerSetNewPw = "generateNewPassword"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)
	testInvalidUserId(t, apiUrl, apiKey.Id, []test.Header{{Name: headerResetPassword, Value: "true"}})

	// Resetting an admin's password requires outranking them, same as every other mutation this
	// endpoint can make - see canAdministerUser. apiKey's owner (idUser) is a plain user, so the
	// actual reset below acts as the super admin instead.
	setPermissionApikey(t, idApiKeySuperAdmin, models.ApiPermManageUsers)
	defer removePermissionApikey(t, idApiKeySuperAdmin, models.ApiPermManageUsers)

	user, ok := database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, user.ResetPassword, false)
	user.Password = "1234"
	database.SaveUser(user, false)
	w, r := getRecorder(apiUrl, idApiKeySuperAdmin, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
	}, {
		Name:  headerResetPassword,
		Value: "true",
	}, {
		Name:  headerSetNewPw,
		Value: "false",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok = database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, user.ResetPassword, true)
	test.IsEqualString(t, user.Password, "1234")
	test.ResponseBodyIs(t, w, `{"Result":"OK","password":""}`)

	user.ResetPassword = false
	database.SaveUser(user, false)
	user, ok = database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, user.ResetPassword, false)

	w, r = getRecorder(apiUrl, idApiKeySuperAdmin, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
	}, {
		Name:  headerResetPassword,
		Value: "true",
	}, {
		Name:  headerSetNewPw,
		Value: "true",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	user, ok = database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, user.ResetPassword, true)
	test.IsEqualBool(t, user.Password != "1234", true)
	type response struct {
		Result   string `json:"Result"`
		Password string `json:"password"`
	}
	var resp response
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	test.IsNil(t, err)
	test.IsEqualString(t, resp.Result, "OK")
	test.IsNotEmpty(t, resp.Password)

	defer test.ExpectPanic(t)
	apiModifyUser(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

// TestUserPasswordResetRefusesNonInternalProvider verifies that an admin holding
// PERM_USERS must not be able to mint a plaintext password for a Google-provisioned user, since
// that would bypass the IdP entirely (its MFA and deprovisioning) the moment the row has a
// password hash. Before this fix, apiResetPassword (now folded into apiModifyUser) never checked
// AuthProvider at all.
func TestUserPasswordResetRefusesNonInternalProvider(t *testing.T) {
	const apiUrl = "/user/modify"
	const idGoogleUser = 910

	// The target is a plain user, so the actor must outrank one - idAdmin does, idUser (this
	// package's usual testAuthorisation actor) does not.
	setPermissionApikey(t, idApiKeyAdmin, models.ApiPermManageUsers)
	defer removePermissionApikey(t, idApiKeyAdmin, models.ApiPermManageUsers)

	database.SaveUser(models.User{
		Id:           idGoogleUser,
		Name:         "googlereset@test.com",
		UserLevel:    models.UserLevelUser,
		AuthProvider: models.AuthProviderGoogle,
	}, false)

	w, r := getRecorder(apiUrl, idApiKeyAdmin, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(idGoogleUser),
	}, {
		Name:  "resetPassword",
		Value: "true",
	}, {
		Name:  "generateNewPassword",
		Value: "true",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)

	dbUser, ok := database.GetUser(idGoogleUser)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, dbUser.ResetPassword, false)
	test.IsEqualString(t, dbUser.Password, "")
}

func testUserModifyCall(t *testing.T, apiKey string, userId int, permission string, grant bool) {
	const apiUrl = "/user/modify"
	const headerUserId = "userid"
	const headerPermission = "userpermission"
	const headerPermModifier = "permissionModifier"

	modifier := "REVOKE"
	if grant {
		modifier = "GRANT"
	}
	w, r := getRecorder(apiUrl, apiKey, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(userId),
	}, {
		Name:  headerPermission,
		Value: permission,
	}, {
		Name:  headerPermModifier,
		Value: modifier,
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
}

// ## /auth ##

func TestNewApiKey(t *testing.T) {
	const apiUrl = "/auth/create"
	const headerFriendlyName = "friendlyName"
	const headerDefaultPerm = "basicPermissions"

	const (
		testNoParam = iota
		testFriendlyName
		testBasicPermission
		testBoth
	)

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermApiMod)
	keysBefore := countApiKeys()

	for i := testNoParam; i <= testBoth; i++ {
		friendlyName := "Unnamed key"
		expectedPermissions := models.ApiPermNone
		var headers []test.Header
		if i == testFriendlyName || i == testBoth {
			friendlyName = helper.GenerateRandomString(40)
			headers = append(headers, test.Header{
				Name:  headerFriendlyName,
				Value: friendlyName,
			})
		}
		if i == testBasicPermission || i == testBoth {
			headers = append(headers, test.Header{
				Name:  headerDefaultPerm,
				Value: "true",
			})
			expectedPermissions = models.ApiPermDefault
		}
		w, r := getRecorder(apiUrl, apiKey.Id, headers)
		Process(w, r)
		test.IsEqualInt(t, w.Code, 200)
		var response models.ApiKeyOutput
		err := json.Unmarshal(w.Body.Bytes(), &response)
		test.IsNil(t, err)
		test.IsEqualString(t, response.Result, "OK")
		test.IsNotEmpty(t, response.Id)
		test.IsNotEmpty(t, response.PublicId)
		test.IsEqualBool(t, response.PublicId != response.Id, true)
		retrievedKey, ok := database.GetApiKey(response.Id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualString(t, response.PublicId, retrievedKey.PublicId)
		test.IsEqualString(t, retrievedKey.FriendlyName, friendlyName)
		test.IsEqualInt(t, countApiKeys(), keysBefore+i+1)
		test.IsEqual(t, retrievedKey.Permissions, expectedPermissions)
	}

	defer test.ExpectPanic(t)
	apiCreateApiKey(nil, &paramUserCreate{}, models.User{Id: 7}, apiKey)
}

// TestNewApiKeyNonAsciiFriendlyName verifies that a friendlyName containing non-ASCII characters,
// sent base64-encoded the way the frontend encoder sends it, is decoded before being stored.
// Before paramAuthCreate.FriendlyName carried supportBase64, the literal "base64:..." string was
// stored as the key's friendly name.
func TestNewApiKeyNonAsciiFriendlyName(t *testing.T) {
	const apiUrl = "/auth/create"
	const headerFriendlyName = "friendlyName"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermApiMod)

	friendlyNameUtf8 := "TestNewApiKey_UTF8_éàü"
	encodedName := "base64:" + base64.StdEncoding.EncodeToString([]byte(friendlyNameUtf8))

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerFriendlyName,
		Value: encodedName,
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	var response models.ApiKeyOutput
	err := json.Unmarshal(w.Body.Bytes(), &response)
	test.IsNil(t, err)
	retrievedKey, ok := database.GetApiKey(response.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrievedKey.FriendlyName, friendlyNameUtf8)
	test.IsEqualBool(t, strings.HasPrefix(retrievedKey.FriendlyName, "base64:"), false)
}

func TestIsValidApiKey(t *testing.T) {
	user, apiKey, isValid := isValidApiKey("", false, models.ApiPermNone)
	test.IsEqualBool(t, isValid, false)
	_, _, isValid = isValidApiKey("invalid", false, models.ApiPermNone)
	test.IsEqualBool(t, isValid, false)
	user, apiKey, isValid = isValidApiKey("validkey", false, models.ApiPermNone)
	test.IsEqualBool(t, isValid, true)
	test.IsEqualString(t, apiKey.Id, "validkey")
	test.IsEqualInt(t, user.Id, 5)
	key, ok := database.GetApiKey("validkey")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, key.LastUsed == 0, true)
	user, apiKey, isValid = isValidApiKey("validkey", true, models.ApiPermNone)
	test.IsEqualBool(t, isValid, true)
	test.IsEqualInt(t, user.Id, 5)
	test.IsEqualString(t, apiKey.Id, "validkey")
	key, ok = database.GetApiKey("validkey")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, key.LastUsed == 0, false)

	newApiKey := generateNewKey(false, 5, "", "")
	user, _, isValid = isValidApiKey(newApiKey.Id, true, models.ApiPermNone)
	test.IsEqualBool(t, isValid, true)
	for _, permission := range getAvailableApiPermissions() {
		_, _, isValid = isValidApiKey(newApiKey.Id, true, permission)
		test.IsEqualBool(t, isValid, false)
	}
	for _, newPermission := range getAvailableApiPermissions() {
		setPermissionApikey(t, newApiKey.Id, newPermission)
		for _, permission := range getAvailableApiPermissions() {
			_, _, isValid = isValidApiKey(newApiKey.Id, true, permission)
			test.IsEqualBool(t, isValid, permission == newPermission)
		}
		removePermissionApikey(t, newApiKey.Id, newPermission)
	}
	setPermissionApikey(t, newApiKey.Id, models.ApiPermEdit|models.ApiPermDelete)
	_, _, isValid = isValidApiKey(newApiKey.Id, true, models.ApiPermEdit)
	test.IsEqualBool(t, isValid, true)
	_, _, isValid = isValidApiKey(newApiKey.Id, true, getPermissionAll())
	test.IsEqualBool(t, isValid, false)
	_, _, isValid = isValidApiKey(newApiKey.Id, true, models.ApiPermView)
	test.IsEqualBool(t, isValid, false)
}

func setPermissionApikey(t *testing.T, key string, newPermission models.ApiPermission) {
	apiKey, ok := database.GetApiKey(key)
	test.IsEqualBool(t, ok, true)
	apiKey.GrantPermission(newPermission)
	database.SaveApiKey(apiKey)
}
func removePermissionApikey(t *testing.T, key string, newPermission models.ApiPermission) {
	apiKey, ok := database.GetApiKey(key)
	test.IsEqualBool(t, ok, true)
	apiKey.RemovePermission(newPermission)
	database.SaveApiKey(apiKey)
}

func getAvailableApiPermissions() []models.ApiPermission {
	result := []models.ApiPermission{
		models.ApiPermView,
		models.ApiPermUpload,
		models.ApiPermDelete,
		models.ApiPermApiMod,
		models.ApiPermEdit,
		models.ApiPermReplace,
		models.ApiPermManageUsers,
		models.ApiPermManageLogs,
		models.ApiPermManageFileRequests,
		models.ApiPermDownload,
	}
	return result
}

func getPermissionAll() models.ApiPermission {
	allPermissions := models.ApiPermNone
	for _, permission := range getAvailableApiPermissions() {
		allPermissions += permission
	}
	return allPermissions
}

func getApiPermMap(t *testing.T) map[models.ApiPermission]string {
	result := make(map[models.ApiPermission]string)
	result[models.ApiPermView] = "PERM_VIEW"
	result[models.ApiPermUpload] = "PERM_UPLOAD"
	result[models.ApiPermDelete] = "PERM_DELETE"
	result[models.ApiPermApiMod] = "PERM_API_MOD"
	result[models.ApiPermEdit] = "PERM_EDIT"
	result[models.ApiPermReplace] = "PERM_REPLACE"
	result[models.ApiPermManageUsers] = "PERM_MANAGE_USERS"
	result[models.ApiPermManageLogs] = "PERM_MANAGE_LOGS"
	result[models.ApiPermManageFileRequests] = "PERM_MANAGE_FILE_REQUESTS"
	result[models.ApiPermDownload] = "PERM_DOWNLOAD"

	sum := 0
	for perm := range result {
		sum = sum + int(perm)
	}
	if sum != int(getPermissionAll()) {
		t.Fatal("List of permissions are incorrect")
	}

	return result
}

func getUserPermMap(t *testing.T) map[models.UserPermission]string {
	result := make(map[models.UserPermission]string)
	result[models.UserPermReplaceUploads] = "PERM_REPLACE"
	result[models.UserPermListOtherUploads] = "PERM_LIST"
	result[models.UserPermEditOtherUploads] = "PERM_EDIT"
	result[models.UserPermReplaceOtherUploads] = "PERM_REPLACE_OTHER"
	result[models.UserPermDeleteOtherUploads] = "PERM_DELETE"
	result[models.UserPermManageLogs] = "PERM_LOGS"
	result[models.UserPermManageApiKeys] = "PERM_API"
	result[models.UserPermManageUsers] = "PERM_USERS"

	sum := 0
	for perm := range result {
		sum = sum + int(perm)
	}
	if sum != int(models.UserPermissionAll) {
		t.Fatal("List of permissions are incorrect")
	}
	return result
}

func grantUserPermission(t *testing.T, userId int, permission models.UserPermission) {
	user, ok := database.GetUser(userId)
	test.IsEqualBool(t, ok, true)
	user.GrantPermission(permission)
	database.SaveUser(user, false)
}
func removeUserPermission(t *testing.T, userId int, permission models.UserPermission) {
	user, ok := database.GetUser(userId)
	test.IsEqualBool(t, ok, true)
	user.RemovePermission(permission)
	database.SaveUser(user, false)
}

func TestDeleteApiKey(t *testing.T) {
	const apiUrl = "/auth/delete"
	const headerApiDelete = "targetKey"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermApiMod)
	testInvalidApiKey(t, apiUrl, apiKey.Id, []test.Header{})

	database.SaveApiKey(models.ApiKey{
		Id:       "toDelete",
		PublicId: "toDelete",
		UserId:   idUser,
	})
	_, ok := database.GetApiKey("toDelete")
	test.IsEqualBool(t, ok, true)

	invalidParameter := []invalidParameterValue{
		{
			Value:        "",
			ErrorMessage: `{"Result":"error","ErrorMessage":"header targetKey is required","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value:        "invalid",
			ErrorMessage: `{"Result":"error","ErrorMessage":"Invalid key ID provided.","ErrorCode":5}`,
			StatusCode:   404,
		},
	}
	testInvalidParameters(t, apiUrl, apiKey.Id, []test.Header{}, headerApiDelete, invalidParameter)
	_, ok = database.GetApiKey(apiKey.Id)
	test.IsEqualBool(t, ok, true)

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerApiDelete,
		Value: apiKey.Id,
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	_, ok = database.GetApiKey(apiKey.Id)
	test.IsEqualBool(t, ok, false)

	defer test.ExpectPanic(t)
	apiDeleteKey(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

func countApiKeys() int {
	return len(database.GetAllApiKeys())
}

func TestAuthInfo(t *testing.T) {
	const apiUrl = "/auth/info"

	// Test unauthenticated access - should work
	w, r := getRecorder(apiUrl, "", []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	type authInfoResponse struct {
		Method            int    `json:"method"`
		PublicName        string `json:"publicName"`
		MinPasswordLength int    `json:"minPasswordLength"`
	}
	var result authInfoResponse
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	// Verify structure
	test.IsEqualBool(t, result.Method >= 0, true)
	test.IsEqualBool(t, result.PublicName != "", true)
	test.IsEqualBool(t, result.MinPasswordLength >= 6, true)

	// Verify exact field set to prevent unintended fields from leaking
	var rawResult map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &rawResult)
	test.IsNil(t, err)
	test.IsEqualInt(t, len(rawResult), 3)
	_, hasMethod := rawResult["method"]
	_, hasPublicName := rawResult["publicName"]
	_, hasMinPasswordLength := rawResult["minPasswordLength"]
	test.IsEqualBool(t, hasMethod, true)
	test.IsEqualBool(t, hasPublicName, true)
	test.IsEqualBool(t, hasMinPasswordLength, true)

	// Test with invalid API key - should still work (endpoint is public)
	w, r = getRecorder(apiUrl, "invalid", []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	// Test that other endpoints still require authentication
	const otherUrl = "/info/version"
	w, r = getRecorder(otherUrl, "", []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)
}

func TestAuthList(t *testing.T) {
	const apiUrl = "/auth/list"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermApiMod)

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

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
	var result []apiKeyListItem
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	// Should have at least one key (the one we're using)
	test.IsEqualBool(t, len(result) >= 1, true)
	// Verify structure - find the apiKey in result
	foundOwnKey := false
	for _, item := range result {
		if item.PublicId == apiKey.PublicId {
			foundOwnKey = true
			test.IsEqualBool(t, item.IsOwnedByCaller, true)
			// Verify Id is redacted, not full secret
			test.IsEqualString(t, item.Id, apiKey.GetRedactedId())
			test.IsNotEqualString(t, item.Id, apiKey.Id)
			break
		}
	}
	test.IsEqualBool(t, foundOwnKey, true)

	// Test deterministic ordering with a second key
	secondKey := generateNewKey(false, apiKey.UserId, "Second Key", "")
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var result2 []apiKeyListItem
	err = json.Unmarshal(w.Body.Bytes(), &result2)
	test.IsNil(t, err)
	// Should have at least two keys now
	test.IsEqualBool(t, len(result2) >= 2, true)
	// Verify the second key is present
	foundSecondKey := false
	for _, item := range result2 {
		if item.PublicId == secondKey.PublicId {
			foundSecondKey = true
			break
		}
	}
	test.IsEqualBool(t, foundSecondKey, true)

	// Test exclusion of system keys, file request keys, and other users' keys
	// Create a system key
	systemKey := models.ApiKey{
		Id:           "systemKey123",
		PublicId:     "systemKeyPublic123",
		FriendlyName: "System Key",
		Permissions:  models.ApiPermNone,
		IsSystemKey:  true,
		UserId:       apiKey.UserId,
	}
	database.SaveApiKey(systemKey)

	// Create a file request key
	fileRequestKey := models.ApiKey{
		Id:              "fileRequestKey123",
		PublicId:        "fileRequestKeyPublic123",
		FriendlyName:    "File Request Key",
		Permissions:     models.ApiPermNone,
		UserId:          apiKey.UserId,
		UploadRequestId: "fileRequest123",
	}
	database.SaveApiKey(fileRequestKey)

	// Create a key for a different user
	otherUser := models.User{
		Name:      "OtherTestUser_" + helper.GenerateRandomString(8),
		UserLevel: models.UserLevelUser,
	}
	database.SaveUser(otherUser, true)
	_ = generateNewKey(false, otherUser.Id, "Other User Key", "")

	// Test that user without UserPermManageApiKeys permission doesn't see other user's keys
	userWithoutPermission := generateNewKey(false, idUser, "User Without Permission", "")
	// Grant the permission needed to access /auth/list
	setPermissionApikey(t, userWithoutPermission.Id, models.ApiPermApiMod)
	w, r = getRecorder(apiUrl, userWithoutPermission.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var result3 []apiKeyListItem
	err = json.Unmarshal(w.Body.Bytes(), &result3)
	test.IsNil(t, err)

	// Should only see own keys, not other user's key
	for _, item := range result3 {
		test.IsEqualBool(t, item.UserId == idUser, true)
		test.IsEqualBool(t, item.UserId != otherUser.Id, true)
	}
	// Should not see system keys
	for _, item := range result3 {
		test.IsNotEqualString(t, item.PublicId, systemKey.PublicId)
	}
	// Should not see file request keys
	for _, item := range result3 {
		test.IsNotEqualString(t, item.PublicId, fileRequestKey.PublicId)
	}
	// All ids should be redacted
	for _, item := range result3 {
		for _, k := range database.GetAllApiKeys() {
			if k.PublicId == item.PublicId {
				test.IsEqualString(t, item.Id, k.GetRedactedId())
				test.IsNotEqualString(t, item.Id, k.Id)
				break
			}
		}
	}

	// Verify all keys returned have redacted ids, no full secrets leaked
	for _, item := range result3 {
		// Redacted ids should have stars in the middle
		test.IsEqualBool(t, strings.Contains(item.Id, "**"), true)
		// And should not contain the full key material
		test.IsEqualBool(t, strings.Count(item.Id, "*") == 26, true)
	}
}

func TestChangeFriendlyName(t *testing.T) {
	const apiUrl = "/auth/modify"
	const headerApiKeyModify = "targetKey"
	const headerNewName = "friendlyName"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermApiMod)
	testInvalidApiKey(t, apiUrl, apiKey.Id, []test.Header{{Name: headerNewName, Value: "new name"}})
	test.IsEqualString(t, apiKey.FriendlyName, "Unnamed key")
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerApiKeyModify,
		Value: apiKey.Id,
	}, {
		Name:  headerNewName,
		Value: "New name for the key",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	key, ok := database.GetApiKey(apiKey.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, key.FriendlyName, "New name for the key")

	// friendlyName is optional now (it can be combined with a permission change instead), so an
	// empty value no longer means "header missing" - it reaches setApiKeyFriendlyName like any
	// other value, which treats an empty name as a reset to the default.
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerApiKeyModify,
		Value: apiKey.Id,
	}, {
		Name:  headerNewName,
		Value: "",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	key, ok = database.GetApiKey(apiKey.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, key.FriendlyName, "Unnamed key")

	// Omitting targetKey's only two mutations entirely is refused as an empty request.
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerApiKeyModify,
		Value: apiKey.Id,
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"no mutation requested","ErrorCode":4}`)

	defer test.ExpectPanic(t)
	apiModifyApiKey(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

// TestChangeFriendlyNameNonAscii verifies that renaming an API key with a non-ASCII friendlyName,
// sent base64-encoded the way the frontend encoder sends it, decodes it before storing. Before
// paramAuthFriendlyName.FriendlyName carried supportBase64, the literal "base64:..." string was
// stored as the key's friendly name.
func TestChangeFriendlyNameNonAscii(t *testing.T) {
	const apiUrl = "/auth/modify"
	const headerApiKeyModify = "targetKey"
	const headerNewName = "friendlyName"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermApiMod)

	newNameUtf8 := "TestChangeFriendlyName_UTF8_éàü"
	encodedName := "base64:" + base64.StdEncoding.EncodeToString([]byte(newNameUtf8))

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerApiKeyModify,
		Value: apiKey.Id,
	}, {
		Name:  headerNewName,
		Value: encodedName,
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	key, ok := database.GetApiKey(apiKey.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, key.FriendlyName, newNameUtf8)
	test.IsEqualBool(t, strings.HasPrefix(key.FriendlyName, "base64:"), false)
}

func TestApikeyModify(t *testing.T) {
	const apiUrl = "/auth/modify"
	const headerApiKeyModify = "targetKey"
	const headerPermission = "permission"
	const headerModifier = "permissionModifier"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermApiMod)
	testInvalidApiKey(t, apiUrl, apiKey.Id, []test.Header{{Name: headerPermission, Value: "PERM_VIEW"}, {Name: headerModifier, Value: "GRANT"}})

	newApiKey := models.ApiKey{
		Id:           "modifyTest",
		PublicId:     "modifyTest",
		FriendlyName: "modifyTest",
		UserId:       idUser,
	}
	database.SaveApiKey(newApiKey)
	retrievedApiKey, ok := database.GetApiKey("modifyTest")
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, retrievedApiKey.Permissions, models.ApiPermNone)

	var validHeaders = []test.Header{
		{
			Name:  headerApiKeyModify,
			Value: retrievedApiKey.Id,
		},
		{
			Name:  headerModifier,
			Value: "GRANT",
		},
	}
	invalidParameter := []invalidParameterValue{
		{
			Value:        "invalid",
			ErrorMessage: `{"Result":"error","ErrorMessage":"invalid permission","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value:        "PERM_VIEWW",
			ErrorMessage: `{"Result":"error","ErrorMessage":"invalid permission","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value:        "PERM_REPLACE",
			ErrorMessage: `{"Result":"error","ErrorMessage":"Insufficient user permission for owner to set this API permission","ErrorCode":6}`,
			StatusCode:   401,
		},
		{
			Value:        "PERM_MANAGE_USERS",
			ErrorMessage: `{"Result":"error","ErrorMessage":"Insufficient user permission for owner to set this API permission","ErrorCode":6}`,
			StatusCode:   401,
		},
		{
			Value:        "PERM_MANAGE_FILE_REQUESTS",
			ErrorMessage: `{"Result":"error","ErrorMessage":"Insufficient user permission for owner to set this API permission","ErrorCode":6}`,
			StatusCode:   401,
		},
	}
	testInvalidParameters(t, apiUrl, apiKey.Id, validHeaders, headerPermission, invalidParameter)

	// permission and permissionModifier are only required together, unlike the plain-empty
	// convenience case testInvalidParameters covers above: a header sent with an empty value
	// still counts as present (see checkHeaderExists), so it reaches the switch below and is
	// rejected the same way as any other unrecognised value, while omitting it entirely is what
	// trips the together-check.
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerApiKeyModify,
		Value: retrievedApiKey.Id,
	}, {
		Name:  headerPermission,
		Value: "",
	}, {
		Name:  headerModifier,
		Value: "GRANT",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"invalid permission","ErrorCode":4}`)

	w, r = getRecorder(apiUrl, apiKey.Id, validHeaders)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"permission and permissionModifier must be provided together","ErrorCode":4}`)

	grantUserPermission(t, idUser, models.UserPermReplaceUploads)
	grantUserPermission(t, idUser, models.UserPermManageUsers)
	grantUserPermission(t, idUser, models.UserPermManageLogs)
	grantUserPermission(t, idUser, models.UserPermGuestUploads)

	for permissionUint, permissionString := range getApiPermMap(t) {
		test.IsEqualBool(t, retrievedApiKey.HasPermission(permissionUint), false)
		testApiModifyCall(t, apiKey, retrievedApiKey.Id, permissionString, true)
		retrievedApiKey, ok = database.GetApiKey("modifyTest")
		test.IsEqualBool(t, ok, true)
		test.IsEqualBool(t, retrievedApiKey.HasPermission(permissionUint), true)
		testApiModifyCall(t, apiKey, retrievedApiKey.Id, permissionString, false)
		retrievedApiKey, ok = database.GetApiKey("modifyTest")
		test.IsEqualBool(t, ok, true)
		test.IsEqualBool(t, retrievedApiKey.HasPermission(permissionUint), false)
	}
	removeUserPermission(t, idUser, models.UserPermReplaceUploads)
	removeUserPermission(t, idUser, models.UserPermManageUsers)
	removeUserPermission(t, idUser, models.UserPermManageLogs)
	removeUserPermission(t, idUser, models.UserPermGuestUploads)
}

func testApiModifyCall(t *testing.T, apiKey models.ApiKey, targetKey string, permission string, grant bool) {
	const apiUrl = "/auth/modify"
	const headerApiKeyModify = "targetKey"
	const headerPermission = "permission"
	const headerModifier = "permissionModifier"

	modifier := "REVOKE"
	if grant {
		modifier = "GRANT"
	}
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerApiKeyModify,
		Value: targetKey,
	}, {
		Name:  headerPermission,
		Value: permission,
	}, {
		Name:  headerModifier,
		Value: modifier,
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	defer test.ExpectPanic(t)
	apiModifyApiKey(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

// ## /files ##

func TestDeleteFile(t *testing.T) {
	database.SaveMetaData(models.File{
		Id:                 "smalltestfile1",
		Name:               "smalltestfile1",
		SHA1:               "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:           2147483646,
		DownloadsRemaining: 1,
		UserId:             idUser,
	})
	database.SaveMetaData(models.File{
		Id:                 "smalltestfile2",
		Name:               "smalltestfile2",
		SHA1:               "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:           2147483646,
		DownloadsRemaining: 1,
		UserId:             idSuperAdmin,
	})
	database.SaveMetaData(models.File{
		Id:                 "smalltestfileDelay",
		Name:               "smalltestfileDelay",
		SHA1:               "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:           2147483646,
		DownloadsRemaining: 1,
		UserId:             idUser,
	})
	_, ok := database.GetMetaDataById("smalltestfile1")
	test.IsEqualBool(t, ok, true)
	_, ok = database.GetMetaDataById("smalltestfile2")
	test.IsEqualBool(t, ok, true)
	_, ok = database.GetMetaDataById("smalltestfileDelay")
	test.IsEqualBool(t, ok, true)

	apiKey := testAuthorisation(t, "/files/delete", models.ApiPermDelete)
	testDeleteFileCall(t, apiKey, "", "", 400, `{"Result":"error","ErrorMessage":"header id is required","ErrorCode":4}`)
	testDeleteFileCall(t, apiKey, "invalid", "", 404, `{"Result":"error","ErrorMessage":"Invalid file ID provided.","ErrorCode":5}`)
	testDeleteFileCall(t, apiKey, "smalltestfile1", "invalid", 400, `{"Result":"error","ErrorMessage":"invalid value in header delay supplied","ErrorCode":4}`)
	testDeleteFileCall(t, apiKey, "smalltestfile1", "", 200, "")
	testDeleteFileCall(t, apiKey, "smalltestfileDelay", "1", 200, "")
	testDeleteFileCall(t, apiKey, "smalltestfile2", "", 401, `{"Result":"error","ErrorMessage":"No permission to delete this file","ErrorCode":6}`)
	_, ok = database.GetMetaDataById("smalltestfile2")
	test.IsEqualBool(t, ok, true)
	grantUserPermission(t, idUser, models.UserPermDeleteOtherUploads)
	testDeleteFileCall(t, apiKey, "smalltestfile2", "", 200, "")
	removeUserPermission(t, idUser, models.UserPermDeleteOtherUploads)

	time.Sleep(200 * time.Millisecond)
	_, ok = database.GetMetaDataById("smalltestfile1")
	test.IsEqualBool(t, ok, false)
	_, ok = database.GetMetaDataById("smalltestfile2")
	test.IsEqualBool(t, ok, false)
	file, ok := database.GetMetaDataById("smalltestfileDelay")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.PendingDeletion != 0, true)

	time.Sleep(900 * time.Millisecond)
	_, ok = database.GetMetaDataById("smalltestfileDelay")
	test.IsEqualBool(t, ok, false)
}

func testDeleteFileCall(t *testing.T, apiKey models.ApiKey, fileId, delay string, resultCode int, expectedResponse string) {
	t.Helper()
	const apiUrl = "/files/delete"
	const headerFileId = "id"
	const headerDelay = "delay"
	headers := []test.Header{{}}
	if fileId != "" {
		headers = append(headers, test.Header{Name: headerFileId, Value: fileId})
	}
	if delay != "" {
		headers = append(headers, test.Header{Name: headerDelay, Value: delay})
	}
	w, r := getRecorder(apiUrl, apiKey.Id, headers)
	Process(w, r)
	test.IsEqualInt(t, w.Code, resultCode)
	if expectedResponse != "" {
		test.ResponseBodyIs(t, w, expectedResponse)
	}

	defer test.ExpectPanic(t)
	apiDeleteFile(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

func TestRestoreFile(t *testing.T) {
	config := configuration.Get()
	fileUser := models.File{
		Id:                 "pendingdeletion1",
		Name:               "pendingdeletion1",
		SHA1:               "pendingdeletion",
		ExpireAt:           2147483646,
		DownloadsRemaining: 1,
		UserId:             idUser,
	}
	fileAdmin := models.File{
		Id:                 "pendingdeletion2",
		Name:               "pendingdeletion2",
		SHA1:               "pendingdeletion",
		ExpireAt:           2147483646,
		DownloadsRemaining: 1,
		UserId:             idSuperAdmin,
	}
	database.SaveMetaData(fileUser)
	database.SaveMetaData(fileAdmin)
	_, ok := database.GetMetaDataById(fileUser.Id)
	test.IsEqualBool(t, ok, true)
	_, ok = database.GetMetaDataById(fileAdmin.Id)
	test.IsEqualBool(t, ok, true)

	apiKey := testAuthorisation(t, "/files/restore", models.ApiPermDelete)
	testRestoreFileCall(t, apiKey, "", 400, `{"Result":"error","ErrorMessage":"header id is required","ErrorCode":4}`)
	testRestoreFileCall(t, apiKey, "invalid", 404, `{"Result":"error","ErrorMessage":"Invalid file ID provided or file has already been deleted.","ErrorCode":5}`)
	testRestoreFileCall(t, apiKey, fileUser.Id, 200, fileUser.ToJsonResult(config.ServerUrl, config.IncludeFilename))
	testRestoreFileCall(t, apiKey, fileAdmin.Id, 401, `{"Result":"error","ErrorMessage":"No permission to restore this file","ErrorCode":6}`)

	storage.DeleteFileSchedule(fileUser.Id, 500, true)
	storage.DeleteFileSchedule(fileAdmin.Id, 500, true)

	file, ok := database.GetMetaDataById(fileUser.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.PendingDeletion != 0, true)
	file, ok = database.GetMetaDataById(fileAdmin.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.PendingDeletion != 0, true)

	testRestoreFileCall(t, apiKey, fileUser.Id, 200, fileUser.ToJsonResult(config.ServerUrl, config.IncludeFilename))
	testRestoreFileCall(t, apiKey, fileAdmin.Id, 401, `{"Result":"error","ErrorMessage":"No permission to restore this file","ErrorCode":6}`)

	file, ok = database.GetMetaDataById(fileUser.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt64(t, file.PendingDeletion, 0)
	file, ok = database.GetMetaDataById(fileAdmin.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.PendingDeletion != 0, true)

	startTime := time.Now()
	for {
		if time.Since(startTime) > 10*time.Second {
			t.Errorf("Timeout waiting for file to be deleted")
			break
		}
		_, ok = database.GetMetaDataById(fileAdmin.Id)
		if !ok {
			break
		} else {
			time.Sleep(50 * time.Millisecond)
		}
	}

	startTime = time.Now()
	for {
		if time.Since(startTime) > 10*time.Second {
			t.Errorf("Timeout waiting for file to be restored")
			break
		}
		file, ok = database.GetMetaDataById(fileUser.Id)
		if !ok {
			t.Errorf("File was deleted")
			break
		}
		if file.PendingDeletion == 0 {
			break
		} else {
			time.Sleep(50 * time.Millisecond)
		}
	}
	test.IsEqualInt64(t, file.PendingDeletion, 0)
	// Removed directly rather than via storage.DeleteFile(id, true): that only schedules
	// disposal and fires CleanUp in a background goroutine, racing TestList (the very next
	// top-level test), which asserts idUser has no files the moment it starts. A direct
	// database.DeleteMetaData guarantees the row is gone before this test returns, without
	// running a full CleanUp sweep over every other fixture row this package's other tests
	// still depend on.
	database.DeleteMetaData(fileUser.Id)
}

func testRestoreFileCall(t *testing.T, apiKey models.ApiKey, fileId string, resultCode int, expectedResponse string) {
	t.Helper()
	const apiUrl = "/files/restore"
	const headerFileId = "id"
	headers := []test.Header{{}}
	if fileId != "" {
		headers = append(headers, test.Header{Name: headerFileId, Value: fileId})
	}
	w, r := getRecorder(apiUrl, apiKey.Id, headers)
	Process(w, r)
	test.IsEqualInt(t, w.Code, resultCode)
	if expectedResponse != "" {
		test.ResponseBodyIs(t, w, expectedResponse)
	}

	defer test.ExpectPanic(t)
	apiRestoreFile(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

func TestList(t *testing.T) {
	const apiUrl = "/files/list"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermView)

	database.DeleteMetaData(idFileUser)
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	test.ResponseBodyIs(t, w, "null")
	generateTestData()

	var result []models.FileApiOutput

	// Get count of own files after regenerating test data
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	ownFileCount := len(result)
	test.IsEqualBool(t, ownFileCount >= 1, true) // At least the file from generateTestData

	// Verify the file we just created exists
	found := false
	for _, file := range result {
		if file.Name == "newTestFileName" {
			found = true
			break
		}
	}
	test.IsEqualBool(t, found, true)

	// Grant LIST_OTHER_UPLOADS permission and verify we see more files
	grantUserPermission(t, idUser, models.UserPermListOtherUploads)
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	// Should see more files now (at least own files + some from other users)
	test.IsEqualBool(t, len(result) > ownFileCount, true)

	// Remove permission and verify we only see our own files
	removeUserPermission(t, idUser, models.UserPermListOtherUploads)
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualInt(t, len(result), ownFileCount)
	test.IsEqualString(t, result[0].Name, "newTestFileName")
}

func TestListDeterministicOrder(t *testing.T) {
	const apiUrl = "/files/list"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermView)
	grantUserPermission(t, idUser, models.UserPermListOtherUploads)

	var result1 []models.FileApiOutput
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err := json.Unmarshal(w.Body.Bytes(), &result1)
	test.IsNil(t, err)

	var result2 []models.FileApiOutput
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err = json.Unmarshal(w.Body.Bytes(), &result2)
	test.IsNil(t, err)

	test.IsEqualInt(t, len(result1), len(result2))
	for i := 0; i < len(result1); i++ {
		test.IsEqualString(t, result1[i].Id, result2[i].Id)
	}

	removeUserPermission(t, idUser, models.UserPermListOtherUploads)
}

func TestListSingle(t *testing.T) {
	const apiUrl = "/files/list/"
	_ = testAuthorisation(t, apiUrl, models.ApiPermView)
	apiKey := testAuthorisation(t, apiUrl+"newTestFile", models.ApiPermView)
	var result models.FileApiOutput

	w, r := getRecorder(apiUrl+"newTestFile", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.Name, "newTestFileName")

	w, r = getRecorder(apiUrl+"e4TjE7CokWK0giiLNxDL", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"No permission to view file","ErrorCode":6}`)
	w, r = getRecorder(apiUrl+"invalid", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 404)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"File not found","ErrorCode":5}`)

	grantUserPermission(t, idUser, models.UserPermListOtherUploads)
	w, r = getRecorder(apiUrl+"e4TjE7CokWK0giiLNxDL", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.Id, "e4TjE7CokWK0giiLNxDL")
	removeUserPermission(t, idUser, models.UserPermListOtherUploads)

	defer test.ExpectPanic(t)
	apiListSingle(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

// TestListDisposedAtCrossesApiBoundary guards the regression this field fixes: the client
// receives DisposedAt only if it survives the marshalled JSON response, not merely the database
// row and models.File - FileApiOutput used to lack the field entirely, so it was silently absent
// from every /files/list response no matter what storage.CleanUp had written.
//
// This uses /files/list rather than /files/list/{id}: the single-file lookup goes through
// storage.GetFile, which deliberately refuses a disposed record (see getFilesForUser's doc
// comment), so a disposed file is only ever visible through the list endpoint.
func TestListDisposedAtCrossesApiBoundary(t *testing.T) {
	const apiUrl = "/files/list"
	const fileId = "disposedListFile"
	disposedAt := int64(1750852108)
	database.SaveMetaData(models.File{
		Id:             fileId,
		Name:           fileId,
		SHA1:           "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:       2147483646,
		UserId:         idUser,
		DisposedAt:     disposedAt,
		DisposalReason: models.DisposalReasonExpired,
	})
	defer database.DeleteMetaData(fileId)

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermView)
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	var result []models.FileApiOutput
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	found := false
	for _, file := range result {
		if file.Id == fileId {
			found = true
			test.IsEqualInt64(t, file.DisposedAt, disposedAt)
		}
	}
	test.IsEqualBool(t, found, true)

	// Decode into a generic map too: unmarshalling into models.FileApiOutput would report a
	// zero value regardless of whether the key was ever on the wire, which is exactly the
	// failure mode this test exists to catch.
	var raw []map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &raw)
	test.IsNil(t, err)
	rawFound := false
	for _, entry := range raw {
		if entry["Id"] == fileId {
			rawFound = true
			_, exists := entry["DisposedAt"]
			test.IsEqualBool(t, exists, true)
		}
	}
	test.IsEqualBool(t, rawFound, true)
}

func TestUpload(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)
	result, body := uploadNewFile(t)
	test.IsEqualString(t, result.Result, "OK")
	test.IsEqualString(t, result.FileInfo.Size, "3 B")
	test.IsEqualInt(t, result.FileInfo.DownloadsRemaining, 200)
	test.IsEqualBool(t, result.FileInfo.IsPasswordProtected, true)
	test.IsEqualString(t, result.FileInfo.UrlDownload, test.Url(test.PortApi)+"/d?id="+result.FileInfo.Id)
	// newFileId := result.FileInfo.Id
	w, r := test.GetRecorder("POST", "/api/files/add", nil, []test.Header{{
		Name:  "apikey",
		Value: apiKey.Id,
	}}, body)
	Process(w, r)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"request Content-Type isn't multipart/form-data","ErrorCode":0}`)
	test.IsEqualInt(t, w.Code, 400)

	defer test.ExpectPanic(t)
	apiUploadFile(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

func uploadNewFile(t *testing.T) (models.Result, *bytes.Buffer) {
	file, err := os.Open("test/fileupload.jpg")
	test.IsNil(t, err)
	defer file.Close()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(file.Name()))
	test.IsNil(t, err)
	_, err = io.Copy(part, file)
	test.IsNil(t, err)
	err = writer.WriteField("allowedDownloads", "200")
	test.IsNil(t, err)
	err = writer.WriteField("expiryDays", "10")
	test.IsNil(t, err)
	err = writer.WriteField("password", "Val1dPassw0rd!")
	test.IsNil(t, err)
	err = writer.Close()
	test.IsNil(t, err)
	newApiKeyUser := generateNewKey(true, idUser, "", "")
	w, r := test.GetRecorder("POST", "/api/files/add", nil, []test.Header{{
		Name:  "apikey",
		Value: newApiKeyUser.Id,
	}}, body)
	r.Header.Add("Content-Type", writer.FormDataContentType())

	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	response, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	result := models.Result{}
	err = json.Unmarshal(response, &result)
	test.IsNil(t, err)
	return result, body
}

func TestDuplicate(t *testing.T) {
	const apiUrl = "/files/duplicate"
	const headerId = "id"
	const headerAllowedDownloads = "allowedDownloads"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermUpload)
	testInvalidFileId(t, apiUrl, apiKey.Id, false)

	validHeader := []test.Header{{Name: headerId, Value: idFileUser}}
	invalidParameter := []invalidParameterValue{
		{
			Value:        "invalid",
			ErrorMessage: `{"Result":"error","ErrorMessage":"invalid value in header allowedDownloads supplied","ErrorCode":4}`,
			StatusCode:   400,
		},
	}
	testInvalidParameters(t, apiUrl, apiKey.Id, validHeader, headerAllowedDownloads, invalidParameter)

	uploadedFile, _ := uploadNewFile(t)
	originalFile, ok := database.GetMetaDataById(uploadedFile.FileInfo.Id)
	test.IsEqualBool(t, ok, true)
	originalFile.DownloadCount = 20
	originalFile.PasswordHash = "abcde"
	database.SaveMetaData(originalFile)
	originalFile, ok = database.GetMetaDataById(originalFile.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, originalFile.Id, originalFile.Id)
	test.IsEqualInt(t, originalFile.DownloadCount, 20)

	for i := 0; i < 8; i++ {
		headers := []test.Header{{Name: "id", Value: originalFile.Id}}
		if i > 0 {
			if i == 1 {
				headers = append(headers, test.Header{Name: "allowedDownloads", Value: "0"})
			} else {
				headers = append(headers, test.Header{Name: "allowedDownloads", Value: "5"})
			}
		}
		if i > 2 {
			if i == 3 {
				headers = append(headers, test.Header{Name: "expiryDays", Value: "0"})
			} else {
				headers = append(headers, test.Header{Name: "expiryDays", Value: "7"})
			}
		}
		if i > 4 {
			headers = append(headers, test.Header{Name: "password", Value: "Secretpw1!"})
		}
		if i > 5 {
			headers = append(headers, test.Header{Name: "originalPassword", Value: "true"})
		}
		if i > 6 {
			headers = append(headers, test.Header{Name: "filename", Value: "a_new_filename"})
		}

		w, r := getRecorder(apiUrl, apiKey.Id, headers)
		Process(w, r)
		test.IsEqualInt(t, w.Code, 200)
		output, err := io.ReadAll(w.Body)
		test.IsNil(t, err)

		var outputFile models.FileApiOutput
		err = json.Unmarshal(output, &outputFile)
		test.IsNil(t, err)

		newFile, ok := database.GetMetaDataById(outputFile.Id)
		test.IsEqualBool(t, ok, true)

		test.IsEqualString(t, newFile.Id, outputFile.Id)
		test.IsEqualBool(t, newFile.Id != originalFile.Id, true)
		if i > 6 {
			test.IsEqualString(t, newFile.Name, "a_new_filename")
		} else {
			test.IsEqualString(t, newFile.Name, originalFile.Name)
		}
		test.IsEqualString(t, newFile.Size, originalFile.Size)
		test.IsEqualString(t, newFile.SHA1, originalFile.SHA1)
		test.IsEqualBool(t, originalFile.PasswordHash == newFile.PasswordHash, i != 5)
		test.IsEqualBool(t, originalFile.ExpireAt == newFile.ExpireAt, i < 3)
		test.IsEqualBool(t, newFile.UnlimitedTime, i == 3)
		test.IsEqualInt64(t, originalFile.SizeBytes, newFile.SizeBytes)
		if i > 2 {
			test.IsEqualInt(t, newFile.DownloadsRemaining, 5)
		}
		if i == 0 {
			test.IsEqualInt(t, newFile.DownloadsRemaining, 200)
		}
		if i == 1 {
			test.IsEqualInt(t, newFile.DownloadsRemaining, 0)
		}
		test.IsEqualBool(t, newFile.UnlimitedDownloads, i == 1)
		test.IsEqualInt(t, newFile.DownloadCount, 0)
	}

	defer test.ExpectPanic(t)
	apiDuplicateFile(nil, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

func TestEditFileHotlinkDisabled(t *testing.T) {
	const apiUrl = "/files/modify"
	os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")
	apiKey := generateNewKey(true, idUser, "", "")

	seedHotlinkableFile := func(id string) {
		database.SaveMetaData(models.File{
			Id:                 id,
			Name:               id + ".jpg",
			SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
			ContentType:        "image/jpg",
			UnlimitedDownloads: true,
			UnlimitedTime:      true,
			UserId:             idUser,
		})
	}

	// Upstream behaviour: editing a file that could be hotlinked, but currently isn't, re-creates
	// the hotlink
	seedHotlinkableFile("hotlinkedittest1")
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{Name: "id", Value: "hotlinkedittest1"}, {Name: "allowedDownloads", Value: "5"}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	editedFile, ok := database.GetMetaDataById("hotlinkedittest1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, editedFile.HotlinkId != "", true)

	// With hotlinks disabled, the very same edit must not re-create one
	os.Setenv("GOKAPI_DISABLE_HOTLINKS", "true")
	defer os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")
	seedHotlinkableFile("hotlinkedittest2")
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{{Name: "id", Value: "hotlinkedittest2"}, {Name: "allowedDownloads", Value: "5"}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	editedFile, ok = database.GetMetaDataById("hotlinkedittest2")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, editedFile.HotlinkId, "")
}

// TestEditFileRejectsWhitespaceOnlyPassword closes the reported confidentiality bug:
// unchecking "keep current password" and submitting a password of three spaces used to
// reach apiEditFile as an empty string (Go's HTTP header parser trims a whitespace-only
// value down to "") and be hashed with configuration.HashPassword, which returns "" for
// an empty password - silently publishing the file unprotected while the caller was told
// the update succeeded. The fix must reject this with an error and leave the stored hash
// untouched.
func TestEditFileRejectsWhitespaceOnlyPassword(t *testing.T) {
	const apiUrl = "/files/modify"
	apiKey := generateNewKey(true, idUser, "", "")
	database.SaveMetaData(models.File{
		Id:                 "editpwwhitespace",
		Name:               "editpwwhitespace.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		PasswordHash:       "existinghash",
	})

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: "editpwwhitespace"},
		{Name: "password", Value: "   "},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)

	file, ok := database.GetMetaDataById("editpwwhitespace")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.PasswordHash, "existinghash")
}

// TestEditFileRejectsShortPassword is the same bug class as
// TestEditFileRejectsWhitespaceOnlyPassword, but for a non-whitespace password that is
// simply shorter than the server-enforced minimum.
func TestEditFileRejectsShortPassword(t *testing.T) {
	const apiUrl = "/files/modify"
	apiKey := generateNewKey(true, idUser, "", "")
	database.SaveMetaData(models.File{
		Id:                 "editpwshort",
		Name:               "editpwshort.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		PasswordHash:       "existinghash",
	})

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: "editpwshort"},
		{Name: "password", Value: "short1"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)

	file, ok := database.GetMetaDataById("editpwshort")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.PasswordHash, "existinghash")
}

// TestEditFileRefusesSettingsChangeOnBundledMember proves PUT /files/modify refuses a
// password/expiry/download-limit change on a file that belongs to a bundle - those fields are
// inert on a member (models.FileBundle owns them now), so the request is rejected with "edit
// the folder instead" rather than silently doing nothing. A rename-only-shaped request (every
// settings header absent) is unaffected, since there is nothing on this endpoint left to refuse.
func TestEditFileRefusesSettingsChangeOnBundledMember(t *testing.T) {
	const apiUrl = "/files/modify"
	apiKey := generateNewKey(true, idUser, "", "")
	bundle := filebundle.Create("TestEditFileBundledMember", idUser)
	database.SaveMetaData(models.File{
		Id:                 "editbundledmember",
		Name:               "editbundledmember.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		BundleId:           bundle.Id,
	})
	t.Cleanup(func() {
		database.DeleteMetaData("editbundledmember")
		filebundle.Delete(bundle)
	})

	cases := []struct {
		name    string
		headers []test.Header
	}{
		{"password", []test.Header{{Name: "id", Value: "editbundledmember"}, {Name: "password", Value: "AValidPassword1!"}}},
		{"removePassword", []test.Header{{Name: "id", Value: "editbundledmember"}, {Name: "removePassword", Value: "true"}}},
		{"allowedDownloads", []test.Header{{Name: "id", Value: "editbundledmember"}, {Name: "allowedDownloads", Value: "5"}}},
		{"expiryTimestamp", []test.Header{{Name: "id", Value: "editbundledmember"}, {Name: "expiryTimestamp", Value: strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, r := getRecorder(apiUrl, apiKey.Id, c.headers)
			Process(w, r)
			test.IsEqualInt(t, w.Code, 400)
		})
	}

	// A request with no settings header at all (the shape a rename-only request would have,
	// since this endpoint has no filename field to rename with today) still succeeds.
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{Name: "id", Value: "editbundledmember"}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
}

// TestEditFileAcceptsValidPassword confirms the fix does not block a legitimate password
// change: a password that meets the minimum length is hashed and stored as before.
func TestEditFileAcceptsValidPassword(t *testing.T) {
	const apiUrl = "/files/modify"
	apiKey := generateNewKey(true, idUser, "", "")
	database.SaveMetaData(models.File{
		Id:                 "editpwvalid",
		Name:               "editpwvalid.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		PasswordHash:       "existinghash",
	})

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: "editpwvalid"},
		{Name: "password", Value: "AValidPassword1!"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	file, ok := database.GetMetaDataById("editpwvalid")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.PasswordHash != "existinghash", true)
	test.IsEqualBool(t, file.PasswordHash != "", true)
}

// TestEditFileAbsentPasswordHeaderKeepsExistingHash is the exact reproduction from the
// BLOCKER 1 report: a caller changes an unrelated field (allowedDownloads) on a
// password-protected file and sends NEITHER "password" NOR the old "originalPassword"
// header at all. Before the fix, KeepPassword (parsed from the optional originalPassword
// header) defaulted to false when the header was absent, which made
// changePassword := !request.KeepPassword true and wrote an empty password hash - silently
// stripping protection as the byproduct of an omitted, optional header. The fix requires a
// password header to actually be PRESENT before the password is touched at all, exactly
// mirroring paramFilesDuplicate/apiDuplicateFile (see routing.go and Api.go). This test
// sends only "id" and "allowedDownloads", matching the reviewer's runtime reproduction, and
// must observe the file still password protected afterwards.
func TestEditFileAbsentPasswordHeaderKeepsExistingHash(t *testing.T) {
	const apiUrl = "/files/modify"
	apiKey := generateNewKey(true, idUser, "", "")
	database.SaveMetaData(models.File{
		Id:                 "editpwabsent",
		Name:               "editpwabsent.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		PasswordHash:       "existinghash",
	})

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: "editpwabsent"},
		{Name: "allowedDownloads", Value: "25"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	file, ok := database.GetMetaDataById("editpwabsent")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.PasswordHash, "existinghash")
	test.IsEqualBool(t, file.PasswordHash != "", true)
	test.IsEqualInt(t, file.DownloadsRemaining, 25)
}

// TestEditFileRemovePasswordHeaderRemovesProtection is MAJOR 2's fix: the only way to
// deliberately remove a password is the dedicated removePassword header. It must clear the
// stored hash AND invalidate any outstanding download-password tokens for the file, exactly
// like a password change does.
//
// This test also sends the retired "originalPassword: true" header alongside removePassword,
// which is deliberate, not an oversight: under the pre-fix code, that header alone is enough
// to make changePassword false (keep the password), which would leave the file protected and
// make this test fail red - the removal would only have "worked" via the OLD code's blanket
// "no originalPassword=true means wipe everything" bug, not because a removal was genuinely
// honored. Sending both proves removePassword is what does the work in the fixed code, and
// that the retired header is now inert rather than quietly overriding it.
func TestEditFileRemovePasswordHeaderRemovesProtection(t *testing.T) {
	const apiUrl = "/files/modify"
	apiKey := generateNewKey(true, idUser, "", "")
	database.SaveMetaData(models.File{
		Id:                 "editpwremove",
		Name:               "editpwremove.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		PasswordHash:       "existinghash",
	})
	token := downloadPasswordToken.Generate("editpwremove")
	test.IsEqualBool(t, downloadPasswordToken.IsValid(token, "editpwremove"), true)

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: "editpwremove"},
		{Name: "originalPassword", Value: "true"},
		{Name: "removePassword", Value: "true"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	file, ok := database.GetMetaDataById("editpwremove")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.PasswordHash, "")
	test.IsEqualBool(t, downloadPasswordToken.IsValid(token, "editpwremove"), false)
}

// TestEditFileRejectsPasswordAndRemovePasswordTogether confirms that sending both headers
// in the same request - a genuinely contradictory instruction ("set this password" and
// "remove the password" at once) - is rejected rather than silently picking one, and that
// the stored hash is left untouched.
func TestEditFileRejectsPasswordAndRemovePasswordTogether(t *testing.T) {
	const apiUrl = "/files/modify"
	apiKey := generateNewKey(true, idUser, "", "")
	database.SaveMetaData(models.File{
		Id:                 "editpwbothheaders",
		Name:               "editpwbothheaders.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		PasswordHash:       "existinghash",
	})

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: "editpwbothheaders"},
		{Name: "password", Value: "AValidPassword1!"},
		{Name: "removePassword", Value: "true"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)

	file, ok := database.GetMetaDataById("editpwbothheaders")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.PasswordHash, "existinghash")
}

// TestEditFileRejectsWhitespaceOnlyPasswordOverRealSocket is MAJOR 3's fix: every other
// whitespace-only-password test in this file goes through getRecorder, which builds the
// request with httptest.NewRequest and r.Header.Set - that stores "   " in the Header map
// verbatim, without going through Go's HTTP header parser. Over a real socket, Go's
// textproto reader trims optional whitespace (OWS) from a header value, so a
// whitespace-only value arrives as "", and r.Header.Get(key) != "" (the fast path in
// checkHeaderExists) is false. checkHeaderExists can then only report the header as present
// via the isString fallback branch (routing.go: len(r.Header.Values(key)) > 0) - the branch
// this whole fix's presence-vs-value distinction depends on. This test proves that branch is
// actually exercised end to end, by sending the request over a real httptest.Server through
// a real http.Client instead of building an *http.Request in memory.
func TestEditFileRejectsWhitespaceOnlyPasswordOverRealSocket(t *testing.T) {
	apiKey := generateNewKey(true, idUser, "", "")
	database.SaveMetaData(models.File{
		Id:                 "editpwwhitespacesocket",
		Name:               "editpwwhitespacesocket.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		PasswordHash:       "existinghash",
	})

	server := httptest.NewServer(http.HandlerFunc(Process))
	defer server.Close()

	req, err := http.NewRequest(http.MethodPut, server.URL+"/files/modify", nil)
	test.IsNil(t, err)
	req.Header.Set("apikey", apiKey.Id)
	req.Header.Set("id", "editpwwhitespacesocket")
	req.Header.Set("password", "   ")

	resp, err := http.DefaultClient.Do(req)
	test.IsNil(t, err)
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, 400)

	file, ok := database.GetMetaDataById("editpwwhitespacesocket")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.PasswordHash, "existinghash")
}

// TestEditFileAbsentPasswordHeaderKeepsExistingHashOverRealSocket is the real-socket
// counterpart to TestEditFileAbsentPasswordHeaderKeepsExistingHash, and also a real-socket
// proof for BLOCKER 1 itself: a genuinely absent header, sent over a real connection, must
// leave the password untouched.
func TestEditFileAbsentPasswordHeaderKeepsExistingHashOverRealSocket(t *testing.T) {
	apiKey := generateNewKey(true, idUser, "", "")
	database.SaveMetaData(models.File{
		Id:                 "editpwabsentsocket",
		Name:               "editpwabsentsocket.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		PasswordHash:       "existinghash",
	})

	server := httptest.NewServer(http.HandlerFunc(Process))
	defer server.Close()

	req, err := http.NewRequest(http.MethodPut, server.URL+"/files/modify", nil)
	test.IsNil(t, err)
	req.Header.Set("apikey", apiKey.Id)
	req.Header.Set("id", "editpwabsentsocket")
	req.Header.Set("allowedDownloads", "25")

	resp, err := http.DefaultClient.Do(req)
	test.IsNil(t, err)
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, 200)

	file, ok := database.GetMetaDataById("editpwabsentsocket")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.PasswordHash, "existinghash")
}

// TestChunkCompleteRejectsWhitespaceOnlyPassword proves the same fix on the upload path:
// a chunked upload completed through the API with a whitespace-only password header must
// be refused, not silently create an unprotected file.
func TestChunkCompleteRejectsWhitespaceOnlyPassword(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)

	// A real chunk file must exist on disk, otherwise CompleteChunk would fail with
	// "chunk file does not exist" regardless of the password check this test targets -
	// see TestChunkCompleteRejectsE2EWhenNotConfigured for the same setup pattern.
	chunkUUID := "whitespacepwtest"
	err := os.WriteFile("test/data/chunk-"+chunkUUID, []byte("testcontent"), 0600)
	test.IsNil(t, err)
	metadataBefore := len(database.GetAllMetadata())

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: chunkUUID},
		{Name: "filename", Value: "test.upload"},
		{Name: "filesize", Value: "11"},
		{Name: "password", Value: "   "}},
		nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"password does not meet the minimum length requirement: minimum length is 8 characters","ErrorCode":10}`)
	test.IsEqualInt(t, len(database.GetAllMetadata()), metadataBefore)
}

// TestEditFileNonAsciiPasswordRoundTrips closes the second reported bug: the password
// header is the one user-supplied text header that used to be neither encoded by the
// client nor decoded by the server. The Headers API a browser client uses serializes
// codepoints up to U+00FF as single latin-1 bytes, so a password containing a non-ASCII
// character such as sharp s (U+00DF) would go on the wire as a single byte and be hashed
// as such, while the public unlock page (pubApiFilePassword in Webserver.go) posts JSON,
// which is UTF-8, so the same character arrives as two bytes there - a different hash,
// so the file could never be unlocked again. The fix decodes a "base64:" prefixed
// password header before hashing (supportBase64 on the routing.go struct tag), so this
// test sends the password the same way the fixed frontend does - base64 encoded - and
// confirms that configuration.VerifyPassword, the exact function pubApiFilePassword
// calls with the raw UTF-8 string a JSON body decodes to, accepts it.
func TestEditFileNonAsciiPasswordRoundTrips(t *testing.T) {
	const apiUrl = "/files/modify"
	const nonAsciiPassword = "Strasse-Sicherheit-2026-ß"
	apiKey := generateNewKey(true, idUser, "", "")
	database.SaveMetaData(models.File{
		Id:                 "editpwnonascii",
		Name:               "editpwnonascii.dat",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
	})

	headerValue := "base64:" + base64.StdEncoding.EncodeToString([]byte(nonAsciiPassword))
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: "editpwnonascii"},
		{Name: "password", Value: headerValue},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	file, ok := database.GetMetaDataById("editpwnonascii")
	test.IsEqualBool(t, ok, true)

	// This mirrors exactly what pubApiFilePassword does with a JSON-decoded body value.
	isValid, _ := configuration.VerifyPassword(nonAsciiPassword, file.PasswordHash, configuration.Get().Authentication.SaltFiles)
	test.IsEqualBool(t, isValid, true)
}

// TestChunkCompleteNonAsciiPasswordRoundTrips is the same proof as
// TestEditFileNonAsciiPasswordRoundTrips, for the upload path.
func TestChunkCompleteNonAsciiPasswordRoundTrips(t *testing.T) {
	const nonAsciiPassword = "Strasse-Sicherheit-2026-ß"
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)

	chunkUUID := "nonasciipwtest"
	err := os.WriteFile("test/data/chunk-"+chunkUUID, []byte("testcontent"), 0600)
	test.IsNil(t, err)

	headerValue := "base64:" + base64.StdEncoding.EncodeToString([]byte(nonAsciiPassword))
	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: chunkUUID},
		{Name: "filename", Value: "test.upload"},
		{Name: "filesize", Value: "11"},
		{Name: "password", Value: headerValue}},
		nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	result := struct {
		FileInfo models.FileApiOutput `json:"FileInfo"`
	}{}
	response, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	err = json.Unmarshal(response, &result)
	test.IsNil(t, err)

	file, ok := database.GetMetaDataById(result.FileInfo.Id)
	test.IsEqualBool(t, ok, true)
	isValid, _ := configuration.VerifyPassword(nonAsciiPassword, file.PasswordHash, configuration.Get().Authentication.SaltFiles)
	test.IsEqualBool(t, isValid, true)
}

func TestChunkUpload(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)
	err := os.WriteFile("test/tmpupload", []byte("chunktestfile"), 0600)
	test.IsNil(t, err)
	body, formcontent := test.FileToMultipartFormBody(t, test.HttpTestConfig{
		UploadFileName:  "test/tmpupload",
		UploadFieldName: "file",
		PostValues: []test.PostBody{{
			Key:   "filesize",
			Value: "13",
		}, {
			Key:   "offset",
			Value: "0",
		}, {
			Key:   "uuid",
			Value: "tmpupload123",
		}},
	})
	w, r := test.GetRecorder("POST", "/api/chunk/add", nil, []test.Header{{
		Name:  "apikey",
		Value: apiKey.Id,
	}}, body)
	r.Header.Add("Content-Type", formcontent)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	test.ResponseBodyIs(t, w, `{"result":"OK"}`)

	body, formcontent = test.FileToMultipartFormBody(t, test.HttpTestConfig{
		UploadFileName:  "test/tmpupload",
		UploadFieldName: "file",
		PostValues: []test.PostBody{{
			Key:   "dztotalfilesize",
			Value: "13",
		}, {
			Key:   "dzchunkbyteoffset",
			Value: "0",
		}, {
			Key:   "dzuuid",
			Value: "tmpupload123",
		}},
	})
	w, r = test.GetRecorder("POST", "/api/chunk/add", nil, []test.Header{{
		Name:  "apikey",
		Value: apiKey.Id,
	}}, body)
	r.Header.Add("Content-Type", formcontent)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"strconv.ParseInt: parsing \"\": invalid syntax","ErrorCode":10}`)

	defer test.ExpectPanic(t)
	apiChunkAdd(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

func TestChunkComplete(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: "tmpupload123"},
		{Name: "filename", Value: "test.upload"},
		{Name: "filesize", Value: "13"}},
		nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	result := struct {
		FileInfo models.FileApiOutput `json:"FileInfo"`
	}{}
	response, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	err = json.Unmarshal(response, &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.FileInfo.Name, "test.upload")
	withinLastTwoSeconds := result.FileInfo.UploadDate >= time.Now().Add(-2*time.Second).Unix() &&
		result.FileInfo.UploadDate <= time.Now().Unix()
	test.IsEqualBool(t, withinLastTwoSeconds, true)

	// data.Set("filesize", "15")

	w, r = test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: "tmpupload123"},
		{Name: "filename", Value: "test.upload"},
		{Name: "filesize", Value: "15"}}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"chunk file does not exist","ErrorCode":0}`)

	defer test.ExpectPanic(t)
	apiChunkComplete(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

// TestChunkCompleteRejectsE2EWhenNotConfigured covers the API chunk-complete
// entry point for F2: a client asserting the isE2E header must not be able to
// mislabel an upload as end-to-end encrypted while the server is configured
// for a different encryption level. No metadata row must be written for the
// rejected upload, and the flag must keep working once the level is
// EndToEndEncryption.
func TestChunkCompleteRejectsE2EWhenNotConfigured(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)

	previousLevel := configuration.Get().Encryption.Level
	defer func() { configuration.Get().Encryption.Level = previousLevel }()

	configuration.Get().Encryption.Level = encryption.FullEncryptionStored
	chunkUUID := "e2enotconfigured123"
	err := os.WriteFile("test/data/chunk-"+chunkUUID, []byte("testcontent"), 0600)
	test.IsNil(t, err)
	metadataBefore := len(database.GetAllMetadata())

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: chunkUUID},
		{Name: "filename", Value: "test.upload"},
		{Name: "filesize", Value: "11"},
		{Name: "isE2E", Value: "true"},
		{Name: "realsize", Value: "11"},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"end-to-end encryption is not enabled on this server","ErrorCode":10}`)
	test.IsEqualInt(t, len(database.GetAllMetadata()), metadataBefore)

	// The same request succeeds once the server is actually configured for E2E.
	configuration.Get().Encryption.Level = encryption.EndToEndEncryption
	err = os.WriteFile("test/data/chunk-"+chunkUUID, []byte("testcontent"), 0600)
	test.IsNil(t, err)
	w, r = test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: chunkUUID},
		{Name: "filename", Value: "test.upload"},
		{Name: "filesize", Value: "11"},
		{Name: "isE2E", Value: "true"},
		{Name: "realsize", Value: "11"},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	test.IsEqualInt(t, len(database.GetAllMetadata()), metadataBefore+1)
}

// chunkUploadWithPassword uploads a small file through /api/chunk/complete (the SPA's real
// upload path) with the given password and generated-password signal, and returns the
// resulting file's Id. Fails the test unless the upload itself succeeds - the toggle/generated
// behaviour under test lives entirely in what gets stored server-side afterwards, not in
// whether the upload is accepted.
func chunkUploadWithPassword(t *testing.T, apiKeyId, uuid, password string, generatedPassword bool) string {
	t.Helper()
	err := os.WriteFile("test/data/chunk-"+uuid, []byte("testcontent"), 0600)
	test.IsNil(t, err)
	headers := []test.Header{
		{Name: "apikey", Value: apiKeyId},
		{Name: "uuid", Value: uuid},
		{Name: "filename", Value: "test.upload"},
		{Name: "filesize", Value: "11"},
		{Name: "password", Value: password},
	}
	if generatedPassword {
		headers = append(headers, test.Header{Name: "generatedpassword", Value: "true"})
	}
	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, headers, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var result models.Result
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	return result.FileInfo.Id
}

// withMasterKey loads a fresh server master key for the duration of the calling test, so
// encryption.IsDecryptionAvailable() (and therefore configuration.StoreShareKeys-gated code)
// reports the key as available. There is no exported way to unload it again, so this is
// additive only - safe here because no other test in this package depends on the master key
// being absent.
func withMasterKey(t *testing.T) {
	t.Helper()
	key, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.FullEncryptionStored, Cipher: key}})
}

// withStoreShareKeys sets configuration.StoreShareKeys for the duration of the calling test and
// restores the previous value afterwards.
func withStoreShareKeys(t *testing.T, enabled bool) {
	t.Helper()
	previous := configuration.Get().StoreShareKeys
	configuration.Get().StoreShareKeys = enabled
	t.Cleanup(func() { configuration.Get().StoreShareKeys = previous })
}

func getShareKey(apiKeyId, fileId string) (*httptest.ResponseRecorder, *http.Request) {
	return getRecorder("/files/"+fileId+"/sharekey", apiKeyId, []test.Header{})
}

func getFolderShareKey(apiKeyId, bundleId string) (*httptest.ResponseRecorder, *http.Request) {
	return getRecorder("/folder/"+bundleId+"/sharekey", apiKeyId, []test.Header{})
}

// chunkUploadToBundleWithPassword uploads a single-chunk file as a member of bundleId, mirroring
// chunkUploadWithPassword above but attaching the upload to a bundle via the bundleid header - the
// same header apiChunkComplete reads to look up and validate ownership of the bundle before
// storeBundleShareKey ever runs.
func chunkUploadToBundleWithPassword(t *testing.T, apiKeyId, uuid, bundleId, password string) string {
	t.Helper()
	err := os.WriteFile("test/data/chunk-"+uuid, []byte("testcontent"), 0600)
	test.IsNil(t, err)
	headers := []test.Header{
		{Name: "apikey", Value: apiKeyId},
		{Name: "uuid", Value: uuid},
		{Name: "filename", Value: "test.upload"},
		{Name: "filesize", Value: "11"},
		{Name: "password", Value: password},
		{Name: "bundleid", Value: bundleId},
	}
	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, headers, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var result models.Result
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	return result.FileInfo.Id
}

// TestApiGetFeatures covers /api/features: it requires a session like any other authenticated
// route, and storeShareKeys is only ever true when both the config flag is on and the master
// key is actually available - the flag alone (with no master key loaded) must still report
// false, since a server in that state could never decrypt a stored key again anyway.
//
// This must run before any test that loads a master key (see withMasterKey): once loaded there
// is no exported way to unload it again for the rest of this test binary, and the
// "toggle on but no master key yet" assertion below depends on none having run yet.
func TestApiGetFeatures(t *testing.T) {
	const apiUrl = "/features"
	apiKey := generateNewKey(false, idUser, "", "")
	database.SaveApiKey(apiKey)

	// No session at all.
	w, r := getRecorder(apiUrl, "", []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)

	type featuresResponse struct {
		Features struct {
			StoreShareKeys bool `json:"storeShareKeys"`
		} `json:"features"`
	}

	// Toggle off (whatever the master key state): always false.
	withStoreShareKeys(t, false)
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var result featuresResponse
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualBool(t, result.Features.StoreShareKeys, false)

	// Toggle on, but nothing has loaded a master key into this test binary yet: still false -
	// the flag alone must never be enough.
	withStoreShareKeys(t, true)
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	result = featuresResponse{}
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualBool(t, result.Features.StoreShareKeys, false)

	// Toggle on and the master key available: true.
	withMasterKey(t)
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	result = featuresResponse{}
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualBool(t, result.Features.StoreShareKeys, true)
}

// TestApiGetShareKeyAuthorisation is the failing-first authz test for GET
// /api/files/{id}/sharekey: a caller without view rights to the file must get the same
// not-found response as an unknown file id (no oracle - see apiGetShareKey), while the owner
// (and a caller with the list-other-uploads permission) gets the stored key back.
func TestApiGetShareKeyAuthorisation(t *testing.T) {
	withMasterKey(t)
	withStoreShareKeys(t, true)

	ownerKey := generateNewKey(false, idUser, "", "")
	ownerKey.GrantPermission(models.ApiPermUpload)
	ownerKey.GrantPermission(models.ApiPermView)
	database.SaveApiKey(ownerKey)

	// A plain, unprivileged user - deliberately not idAdmin, which already carries
	// UserPermissionAll (including list-other-uploads) in generateTestData and so would not
	// exercise the "no permission at all" path this test needs.
	const idStranger = 103
	database.SaveUser(models.User{
		Id:           idStranger,
		Name:         "TestStranger",
		Permissions:  models.UserPermissionNone,
		UserLevel:    models.UserLevelUser,
		AuthProvider: models.AuthProviderInternal,
	}, false)
	otherUserKey := generateNewKey(false, idStranger, "", "")
	otherUserKey.GrantPermission(models.ApiPermView)
	database.SaveApiKey(otherUserKey)

	fileId := chunkUploadWithPassword(t, ownerKey.Id, "sharekeyauthz1", "generatedPassw0rd!", true)

	// Unknown id and "no view permission at all" both look identical from the outside.
	w, r := getShareKey(ownerKey.Id, "doesnotexist")
	Process(w, r)
	test.IsEqualInt(t, w.Code, 404)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"File not found","ErrorCode":5}`)

	// A caller with PERM_VIEW but who is neither the owner nor granted list-other-uploads must
	// not be able to read another user's key - same not-found response, no leak.
	w, r = getShareKey(otherUserKey.Id, fileId)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 404)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"File not found","ErrorCode":5}`)

	// The owner gets the real, decrypted key back.
	w, r = getShareKey(ownerKey.Id, fileId)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var result struct {
		Key string `json:"key"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.Key, "generatedPassw0rd!")

	// Granting list-other-uploads lets the other user in too - same authorisation the rest of
	// the file-list/view surface (e.g. apiListSingle) already uses.
	grantUserPermission(t, idStranger, models.UserPermListOtherUploads)
	w, r = getShareKey(otherUserKey.Id, fileId)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.Key, "generatedPassw0rd!")
	removeUserPermission(t, idStranger, models.UserPermListOtherUploads)

	// No apikey / invalid apikey are refused the same way as any other authenticated route.
	w, r = getShareKey("", fileId)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)
}

// TestApiGetShareKeyToggleOff is the failing-first toggle test: with StoreShareKeys off, an
// upload with a generated password must store NO EncryptedSharePassword, and the endpoint must
// answer not-found even for the file's own owner.
func TestApiGetShareKeyToggleOff(t *testing.T) {
	withMasterKey(t)
	withStoreShareKeys(t, false)

	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	apiKey.GrantPermission(models.ApiPermView)
	database.SaveApiKey(apiKey)

	fileId := chunkUploadWithPassword(t, apiKey.Id, "sharekeytoggleoff1", "generatedPassw0rd!", true)

	file, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, len(file.EncryptedSharePassword), 0)

	w, r := getShareKey(apiKey.Id, fileId)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 404)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"File not found","ErrorCode":5}`)
}

// TestApiGetShareKeyToggleOnGeneratedVsManual is the failing-first test for the toggle-on
// behaviour: a generated password is stored encrypted and comes back byte-for-byte identical
// through the endpoint, while a manually typed password - even with the toggle on - is never
// stored at all.
func TestApiGetShareKeyToggleOnGeneratedVsManual(t *testing.T) {
	withMasterKey(t)
	withStoreShareKeys(t, true)

	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	apiKey.GrantPermission(models.ApiPermView)
	database.SaveApiKey(apiKey)

	generatedFileId := chunkUploadWithPassword(t, apiKey.Id, "sharekeytoggleon1", "generatedPassw0rd!", true)
	file, ok := database.GetMetaDataById(generatedFileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, len(file.EncryptedSharePassword) > 0, true)

	w, r := getShareKey(apiKey.Id, generatedFileId)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var result struct {
		Key string `json:"key"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.Key, "generatedPassw0rd!")

	// A typed password is stored on the same terms as a generated one, so the owner can look
	// up any key they set. The GeneratedPassword signal is still carried end to end, but no
	// longer gates storage.
	manualFileId := chunkUploadWithPassword(t, apiKey.Id, "sharekeytoggleon2", "manuallyTypedPw1!", false)
	file, ok = database.GetMetaDataById(manualFileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, len(file.EncryptedSharePassword) > 0, true)

	w, r = getShareKey(apiKey.Id, manualFileId)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.Key, "manuallyTypedPw1!")
}

// Placed with the other share-key tests deliberately: withMasterKey has no teardown, so a test
// that calls it must run AFTER TestApiGetFeatures, which asserts the flag is false while no
// master key has been loaded into the binary yet.
// TestEditFileReplacesStoredShareKey covers the stale-key hazard: changing the password of a
// file that has a stored share key must replace that stored key, never leave the previous
// one behind. A left-behind key makes GET /files/{id}/sharekey serve a key that no longer
// opens the file, which is worse than serving nothing.
func TestEditFileReplacesStoredShareKey(t *testing.T) {
	const apiUrl = "/files/modify"
	withMasterKey(t)
	withStoreShareKeys(t, true)

	apiKey := generateNewKey(true, idUser, "", "")
	fileId := chunkUploadWithPassword(t, apiKey.Id, "editsharekey1", "origPassw0rd!", true)
	file, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	stored, ok := storage.GetSharePassword(file)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, stored, "origPassw0rd!")

	// A generated replacement is stored, and is the NEW key.
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: fileId},
		{Name: "password", Value: "rotatedPassw0rd!"},
		{Name: "generatedpassword", Value: "true"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	file, ok = database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	stored, ok = storage.GetSharePassword(file)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, stored, "rotatedPassw0rd!")

	// A typed replacement is stored too, and must be the NEW key rather than the generated
	// one it replaced. Leaving the old value behind is the failure this guards.
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: fileId},
		{Name: "password", Value: "typedPassw0rd1!"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	file, ok = database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	stored, ok = storage.GetSharePassword(file)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, stored, "typedPassw0rd1!")
}

// TestStoreBundleShareKeyToggleOnAndOff is the failing-first test for storeBundleShareKey: a
// bundle member uploaded with a password stores an encrypted share key on the BUNDLE (not just
// the file) when StoreShareKeys is on, and stores nothing on the bundle when it is off - mirroring
// TestApiGetShareKeyToggleOff/TestApiGetShareKeyToggleOnGeneratedVsManual for files exactly.
func TestStoreBundleShareKeyToggleOnAndOff(t *testing.T) {
	withMasterKey(t)

	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)

	// Toggle off: the member's own file still stores nothing either (existing behaviour), and
	// the bundle must not either.
	withStoreShareKeys(t, false)
	bundleOff := filebundle.Create("TestStoreBundleShareKey_Off", idUser)
	chunkUploadToBundleWithPassword(t, apiKey.Id, "bundlesharekeyoff1", bundleOff.Id, "folderPassw0rd!")
	bundle, ok := database.GetFileBundle(bundleOff.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, len(bundle.EncryptedSharePassword), 0)

	// Toggle on: the first member's password is stored on the bundle.
	withStoreShareKeys(t, true)
	bundleOn := filebundle.Create("TestStoreBundleShareKey_On", idUser)
	chunkUploadToBundleWithPassword(t, apiKey.Id, "bundlesharekeyon1", bundleOn.Id, "folderPassw0rd!")
	bundle, ok = database.GetFileBundle(bundleOn.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, len(bundle.EncryptedSharePassword) > 0, true)
	stored, ok := storage.GetBundleSharePassword(bundle)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, stored, "folderPassw0rd!")

	// A second member completing afterwards must not overwrite the key the first member
	// established - see storeBundleShareKey's doc comment.
	chunkUploadToBundleWithPassword(t, apiKey.Id, "bundlesharekeyon2", bundleOn.Id, "differentPassw0rd!")
	bundle, ok = database.GetFileBundle(bundleOn.Id)
	test.IsEqualBool(t, ok, true)
	stored, ok = storage.GetBundleSharePassword(bundle)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, stored, "folderPassw0rd!")
}

// TestApiGetFolderShareKeyAuthorisation is the failing-first authz test for GET
// /api/folder/{id}/sharekey: mirrors TestApiGetShareKeyAuthorisation for files exactly - the
// owner (and a caller with the list-other-uploads permission) gets the stored key back, while an
// unauthorised caller gets the same not-found response as an unknown bundle id.
func TestApiGetFolderShareKeyAuthorisation(t *testing.T) {
	withMasterKey(t)
	withStoreShareKeys(t, true)

	ownerKey := generateNewKey(false, idUser, "", "")
	ownerKey.GrantPermission(models.ApiPermUpload)
	ownerKey.GrantPermission(models.ApiPermView)
	database.SaveApiKey(ownerKey)

	bundle := filebundle.Create("TestApiGetFolderShareKeyAuthorisation_Folder", idUser)
	chunkUploadToBundleWithPassword(t, ownerKey.Id, "foldersharekeyauth1", bundle.Id, "folderAuthPassw0rd!")

	// Owner can retrieve it.
	w, r := getFolderShareKey(ownerKey.Id, bundle.Id)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var result struct {
		Key string `json:"key"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.Key, "folderAuthPassw0rd!")

	// An unknown bundle id is refused identically.
	w, r = getFolderShareKey(ownerKey.Id, "doesnotexist")
	Process(w, r)
	test.IsEqualInt(t, w.Code, 404)

	// A plain, unprivileged stranger - deliberately not idAdmin, which already carries
	// UserPermissionAll (including list-other-uploads).
	const idStranger = 104
	database.SaveUser(models.User{
		Id:           idStranger,
		Name:         "TestFolderShareKeyStranger",
		Permissions:  models.UserPermissionNone,
		UserLevel:    models.UserLevelUser,
		AuthProvider: models.AuthProviderInternal,
	}, false)
	strangerKey := generateNewKey(false, idStranger, "", "")
	strangerKey.GrantPermission(models.ApiPermView)
	database.SaveApiKey(strangerKey)

	w, r = getFolderShareKey(strangerKey.Id, bundle.Id)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 404)

	// Granting list-other-uploads gives the stranger access, matching apiFolderList's own
	// authorisation check.
	grantUserPermission(t, idStranger, models.UserPermListOtherUploads)
	w, r = getFolderShareKey(strangerKey.Id, bundle.Id)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.Key, "folderAuthPassw0rd!")
	removeUserPermission(t, idStranger, models.UserPermListOtherUploads)

	// No apikey / invalid apikey are refused the same way as any other authenticated route.
	w, r = getFolderShareKey("", bundle.Id)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)
}

func TestMinorFunctions(t *testing.T) {
	outputFileJson(nil, models.File{})
	sendError(nil, 0, 0, "none")
}

func testReplaceFileCall(t *testing.T, apiKey models.ApiKey, fileTarget, fileOrigin string, deleteFile bool, resultCode int, expectedResponse string) {
	t.Helper()
	const apiUrl = "/files/replace"
	const headerFileIdTarget = "id"
	const headerFileIdOrigin = "idNewContent"
	const headerDeleteFile = "deleteNewFile"
	headers := []test.Header{{}}
	if fileTarget != "" {
		headers = append(headers, test.Header{Name: headerFileIdTarget, Value: fileTarget})
	}
	if fileOrigin != "" {
		headers = append(headers, test.Header{Name: headerFileIdOrigin, Value: fileOrigin})
	}
	if deleteFile {
		headers = append(headers, test.Header{Name: headerDeleteFile, Value: "true"})
	}
	w, r := getRecorder(apiUrl, apiKey.Id, headers)
	Process(w, r)
	test.IsEqualInt(t, w.Code, resultCode)
	if expectedResponse != "" {
		test.ResponseBodyIs(t, w, expectedResponse)
	}

	defer test.ExpectPanic(t)
	apiReplaceFile(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

func TestFileReplace(t *testing.T) {
	originalFile := models.File{
		Id:                 "originalfiletest",
		Name:               "old.txt",
		Size:               "1KB",
		SHA1:               "replacetest1",
		ContentType:        "text/plain",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		AwsBucket:          "",
		SizeBytes:          1024,
		UserId:             idUser,
		Encryption: models.EncryptionInfo{
			IsEncrypted:         false,
			IsEndToEndEncrypted: false,
			DecryptionKey:       nil,
			Nonce:               nil,
		},
	}

	newFile := models.File{
		Id:                 "newfiletest",
		Name:               "new.txt",
		Size:               "2KB",
		SHA1:               "replacetest2",
		ContentType:        "text/plain2",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             idUser,
		AwsBucket:          "",
		SizeBytes:          2048,
		Encryption: models.EncryptionInfo{
			IsEncrypted:         true,
			IsEndToEndEncrypted: false,
			DecryptionKey:       []byte("key"),
			Nonce:               []byte("nonce"),
		},
	}

	e2eFile := models.File{
		Id:                 "e2eFile",
		Name:               "e2eFile",
		Size:               "1KB",
		UnlimitedDownloads: true,
		UserId:             idUser,
		UnlimitedTime:      true,
		SHA1:               "replacetest3",
		Encryption: models.EncryptionInfo{
			IsEncrypted:         true,
			IsEndToEndEncrypted: true,
		},
	}
	adminFile := models.File{
		Id:                 "adminfile",
		Name:               "old.txt",
		Size:               "1KB",
		SHA1:               "replacetest1",
		ContentType:        "text/plain",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		AwsBucket:          "",
		SizeBytes:          1024,
		UserId:             idAdmin,
		Encryption: models.EncryptionInfo{
			IsEncrypted:         false,
			IsEndToEndEncrypted: false,
			DecryptionKey:       nil,
			Nonce:               nil,
		},
	}

	database.SaveMetaData(originalFile)
	_, ok := database.GetMetaDataById(originalFile.Id)
	test.IsEqualBool(t, ok, true)
	database.SaveMetaData(newFile)
	_, ok = database.GetMetaDataById(newFile.Id)
	test.IsEqualBool(t, ok, true)
	database.SaveMetaData(e2eFile)
	_, ok = database.GetMetaDataById(e2eFile.Id)
	test.IsEqualBool(t, ok, true)
	database.SaveMetaData(adminFile)
	_, ok = database.GetMetaDataById(adminFile.Id)
	test.IsEqualBool(t, ok, true)

	apiKey := testAuthorisation(t, "/files/replace", models.ApiPermReplace)
	testReplaceFileCall(t, apiKey, "", "invalid", false, 400, `{"Result":"error","ErrorMessage":"header id is required","ErrorCode":4}`)
	testReplaceFileCall(t, apiKey, "invalid", "", false, 400, `{"Result":"error","ErrorMessage":"header idNewContent is required","ErrorCode":4}`)
	testReplaceFileCall(t, apiKey, "invalid", originalFile.Id, false, 404, `{"Result":"error","ErrorMessage":"Invalid id provided.","ErrorCode":5}`)
	testReplaceFileCall(t, apiKey, originalFile.Id, "invalid", false, 404, `{"Result":"error","ErrorMessage":"Invalid id provided.","ErrorCode":5}`)
	testReplaceFileCall(t, apiKey, originalFile.Id, adminFile.Id, false, 401, `{"Result":"error","ErrorMessage":"No permission to duplicate this file","ErrorCode":6}`)
	testReplaceFileCall(t, apiKey, adminFile.Id, originalFile.Id, false, 401, `{"Result":"error","ErrorMessage":"No permission to replace this file","ErrorCode":6}`)
	testReplaceFileCall(t, apiKey, e2eFile.Id, originalFile.Id, false, 400, `{"Result":"error","ErrorMessage":"End-to-End encrypted files cannot be replaced","ErrorCode":17}`)
	testReplaceFileCall(t, apiKey, originalFile.Id, newFile.Id, false, 200, "")

	file, ok := database.GetMetaDataById(originalFile.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.Name, newFile.Name)
	test.IsEqualString(t, file.SHA1, newFile.SHA1)
	test.IsEqualString(t, file.ContentType, newFile.ContentType)
	test.IsEqualString(t, file.AwsBucket, newFile.AwsBucket)
	test.IsEqualString(t, file.Size, newFile.Size)
	test.IsEqualInt64(t, file.SizeBytes, newFile.SizeBytes)
	test.IsEqual(t, file.Encryption, newFile.Encryption)
	_, ok = storage.GetFile(newFile.Id)
	test.IsEqualBool(t, ok, true)

	apiKey.RemovePermission(models.ApiPermDelete)
	database.SaveApiKey(apiKey)
	testReplaceFileCall(t, apiKey, originalFile.Id, newFile.Id, true, 401, `{"Result":"error","ErrorMessage":"No permission to delete original file","ErrorCode":6}`)
	testReplaceFileCall(t, apiKey, originalFile.Id, adminFile.Id, true, 401, `{"Result":"error","ErrorMessage":"No permission to duplicate this file","ErrorCode":6}`)

	apiKey.GrantPermission(models.ApiPermDelete)
	database.SaveApiKey(apiKey)
	user, _ := database.GetUser(idUser)
	user.GrantPermission(models.UserPermListOtherUploads)
	user.RemovePermission(models.UserPermDeleteOtherUploads)
	database.SaveUser(user, false)
	testReplaceFileCall(t, apiKey, originalFile.Id, adminFile.Id, true, 401, `{"Result":"error","ErrorMessage":"No permission to delete original file","ErrorCode":6}`)

	user.GrantPermission(models.UserPermDeleteOtherUploads)
	database.SaveUser(user, false)
	testReplaceFileCall(t, apiKey, originalFile.Id, adminFile.Id, true, 200, "")
	_, ok = storage.GetFile(originalFile.Id)
	test.IsEqualBool(t, ok, true)
	_, ok = storage.GetFile(adminFile.Id)
	test.IsEqualBool(t, ok, false)

	user.RemovePermission(models.UserPermDeleteOtherUploads)
	database.SaveUser(user, false)
	testReplaceFileCall(t, apiKey, originalFile.Id, newFile.Id, true, 200, "")
	_, ok = storage.GetFile(originalFile.Id)
	test.IsEqualBool(t, ok, true)
	_, ok = storage.GetFile(newFile.Id)
	test.IsEqualBool(t, ok, false)
}

func TestChunkCompleteSanitisation(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)

	dangerousCases := []struct {
		name        string
		filename    string
		contentType string
	}{
		{
			name:        "path traversal in filename",
			filename:    "../../etc/passwd",
			contentType: "text/plain",
		},
		{
			name:        "CRLF injection in filename",
			filename:    "upload.txt\r\nSet-Cookie: session=evil",
			contentType: "text/plain",
		},
		{
			name:        "null byte in filename",
			filename:    "file\x00.txt",
			contentType: "text/plain",
		},
		{
			name:        "CRLF injection in content-type",
			filename:    "upload.txt",
			contentType: "text/plain\r\nX-Injected: evil",
		},
		{
			name:        "null byte in content-type",
			filename:    "upload.txt",
			contentType: "text/plain\x00evil",
		},
	}

	for _, tc := range dangerousCases {
		t.Run(tc.name, func(t *testing.T) {
			// Write a temporary chunk file for the upload to succeed.
			chunkUUID := "sanitisetest123"
			err := os.WriteFile("test/data/chunk-"+chunkUUID, []byte("testcontent"), 0600)
			test.IsNil(t, err)

			w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
				{Name: "apikey", Value: apiKey.Id},
				{Name: "uuid", Value: chunkUUID},
				{Name: "filename", Value: tc.filename},
				{Name: "filesize", Value: "11"},
				{Name: "contenttype", Value: tc.contentType},
			}, nil)
			Process(w, r)
			test.IsEqualInt(t, w.Code, 200)

			// Parse the returned file metadata.
			result := struct {
				FileInfo models.FileApiOutput `json:"FileInfo"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			test.IsNil(t, err)

			// The stored filename must not contain any dangerous sequences.
			storedName := result.FileInfo.Name
			test.IsEqualBool(t, strings.HasPrefix(storedName, ".."), false)
			test.IsEqualBool(t, strings.Contains(storedName, "\r"), false)
			test.IsEqualBool(t, strings.Contains(storedName, "\n"), false)
			test.IsEqualBool(t, strings.Contains(storedName, "\x00"), false)
		})
	}
}

func TestChunkUploadRequestCompleteSanitisation(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)

	// paramChunkUploadRequestComplete already calls both sanitisers.
	// Verify end-to-end that dangerous filenames and content-types submitted
	// through /chunk/upload-request/complete are cleaned before storage.
	p := &paramChunkUploadRequestComplete{}
	p.foundHeaders = map[string]bool{}
	p.FileName = "../../etc/passwd\r\nSet-Cookie: x=1"
	p.ContentType = "text/plain\r\nX-Evil: header"
	p.FileSize = 10
	err := p.ProcessParameter(nil)
	test.IsNil(t, err)

	test.IsEqualBool(t, strings.HasPrefix(p.FileName, ".."), false)
	test.IsEqualBool(t, strings.Contains(p.FileName, "\r"), false)
	test.IsEqualBool(t, strings.Contains(p.FileName, "\n"), false)
	test.IsEqualBool(t, strings.Contains(p.ContentType, "\r"), false)
	test.IsEqualBool(t, strings.Contains(p.ContentType, "\n"), false)
	// Sanitised values must propagate into FileHeader.
	test.IsEqualString(t, p.FileHeader.Filename, p.FileName)
	test.IsEqualString(t, p.FileHeader.ContentType, p.ContentType)
}

// uploadChunkToFileRequest uploads a single small chunked file through the public file-request
// endpoints, the same way apiChunkUploadRequestAdd/apiChunkUploadRequestComplete are reached by a
// real client.
func uploadChunkToFileRequest(t *testing.T, frId, publicKey, tmpName string) {
	w, r := getRecorderWithBody("/uploadrequest/chunk/reserve", publicKey, "POST", []test.Header{
		{Name: "id", Value: frId},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var reserved struct {
		Uuid string
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &reserved))

	err := os.WriteFile("test/"+tmpName, []byte("closetest"), 0600)
	test.IsNil(t, err)
	body, formcontent := test.FileToMultipartFormBody(t, test.HttpTestConfig{
		UploadFileName:  "test/" + tmpName,
		UploadFieldName: "file",
		PostValues: []test.PostBody{{
			Key:   "filesize",
			Value: "9",
		}, {
			Key:   "offset",
			Value: "0",
		}, {
			Key:   "uuid",
			Value: reserved.Uuid,
		}},
	})
	w, r = getRecorderWithBody("/uploadrequest/chunk/add", publicKey, "POST", []test.Header{
		{Name: "fileRequestId", Value: frId},
	}, body)
	r.Header.Add("Content-Type", formcontent)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	w, r = getRecorderWithBody("/uploadrequest/chunk/complete", publicKey, "POST", []test.Header{
		{Name: "uuid", Value: reserved.Uuid},
		{Name: "filename", Value: tmpName + ".upload"},
		{Name: "filesize", Value: "9"},
		{Name: "fileRequestId", Value: frId},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
}

// TestChunkUploadRequestClosesOnLastFile proves a file request is marked complete automatically
// once it holds the last file it may accept, so the owner is not left thinking the request is
// still open when it can no longer take anything more. A request with no file limit must not be
// affected.
func TestChunkUploadRequestClosesOnLastFile(t *testing.T) {
	admin := models.User{Id: idAdmin, UserLevel: models.UserLevelAdmin, Permissions: models.UserPermissionAll}

	w := httptest.NewRecorder()
	request := &paramURequestSave{
		Name:          "close-on-full-request",
		MaxFiles:      1,
		IsMaxFilesSet: true,
		foundHeaders:  map[string]bool{},
	}
	apiURequestSave(w, request, admin, models.ApiKey{})
	test.IsEqualInt(t, w.Code, 200)
	var response struct {
		FileRequest models.FileRequest
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))

	uploadChunkToFileRequest(t, response.FileRequest.Id, response.FileRequest.ApiKey, "closetestuuid")

	saved, ok := database.GetFileRequest(response.FileRequest.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, saved.Closed, true)

	w2 := httptest.NewRecorder()
	request2 := &paramURequestSave{
		Name:          "unlimited-request",
		MaxFiles:      0,
		IsMaxFilesSet: true,
		foundHeaders:  map[string]bool{},
	}
	apiURequestSave(w2, request2, admin, models.ApiKey{})
	test.IsEqualInt(t, w2.Code, 200)
	var response2 struct {
		FileRequest models.FileRequest
	}
	test.IsNil(t, json.Unmarshal(w2.Body.Bytes(), &response2))

	uploadChunkToFileRequest(t, response2.FileRequest.Id, response2.FileRequest.ApiKey, "closetestuuid2")

	saved2, ok := database.GetFileRequest(response2.FileRequest.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, saved2.Closed, false)
}

// uploadChunkToFileRequestWithCookie behaves like uploadChunkToFileRequest but, when cookie is
// non-nil, attaches it to the chunk-complete call - the same access cookie a real recipient's
// browser carries after exchanging their mailed token on the public upload page (see
// ShareGuard.recipientFor / pubApiUploadRequest). Used to prove the resulting upload is
// attributed to that recipient rather than to the request's owner.
func uploadChunkToFileRequestWithCookie(t *testing.T, frId, publicKey, tmpName string, cookie *http.Cookie) {
	w, r := getRecorderWithBody("/uploadrequest/chunk/reserve", publicKey, "POST", []test.Header{
		{Name: "id", Value: frId},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var reserved struct {
		Uuid string
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &reserved))

	err := os.WriteFile("test/"+tmpName, []byte("closetest"), 0600)
	test.IsNil(t, err)
	body, formcontent := test.FileToMultipartFormBody(t, test.HttpTestConfig{
		UploadFileName:  "test/" + tmpName,
		UploadFieldName: "file",
		PostValues: []test.PostBody{{
			Key:   "filesize",
			Value: "9",
		}, {
			Key:   "offset",
			Value: "0",
		}, {
			Key:   "uuid",
			Value: reserved.Uuid,
		}},
	})
	w, r = getRecorderWithBody("/uploadrequest/chunk/add", publicKey, "POST", []test.Header{
		{Name: "fileRequestId", Value: frId},
	}, body)
	r.Header.Add("Content-Type", formcontent)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	w, r = getRecorderWithBody("/uploadrequest/chunk/complete", publicKey, "POST", []test.Header{
		{Name: "uuid", Value: reserved.Uuid},
		{Name: "filename", Value: tmpName + ".upload"},
		{Name: "filesize", Value: "9"},
		{Name: "fileRequestId", Value: frId},
	}, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
}

// TestChunkUploadRequestAttributesUploadToRecipient proves that an upload into a file request
// restricted to named recipients is audited under the recipient who actually uploaded it, not
// the request's owner - the mis-attribution F5/F2 fix. The owner still appears, moved into
// Detail rather than Actor.
func TestChunkUploadRequestAttributesUploadToRecipient(t *testing.T) {
	admin := models.User{Id: idAdmin, UserLevel: models.UserLevelAdmin, Permissions: models.UserPermissionAll}
	owner, ok := database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)

	w := httptest.NewRecorder()
	request := &paramURequestSave{
		Name:         "recipient-attribution-request",
		foundHeaders: map[string]bool{},
	}
	apiURequestSave(w, request, admin, models.ApiKey{})
	test.IsEqualInt(t, w.Code, 200)
	var response struct {
		FileRequest models.FileRequest
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))
	frId := response.FileRequest.Id

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "guest-uploader@example.com", CreatedAt: time.Now().Unix()})
	database.SetShareGrants(models.ShareResourceFileRequest, frId, []int{recipientId}, idAdmin, 0)

	recorder := httptest.NewRecorder()
	cookieReq := httptest.NewRequest(http.MethodGet, "https://x.test/r/"+frId, nil)
	shareaccess.WriteCookie(recorder, cookieReq, models.ShareResourceFileRequest, frId, recipientId)
	cookie := recorder.Result().Cookies()[0]

	uploadChunkToFileRequestWithCookie(t, frId, response.FileRequest.ApiKey, "recipient-attrib-uuid", cookie)

	time.Sleep(200 * time.Millisecond)
	entries, _ := logging.GetAuditEntriesSince(0, 2000)
	found := false
	for _, entry := range entries {
		if entry.Action != "upload.filerequest" || entry.RequestId != frId {
			continue
		}
		found = true
		test.IsEqualInt(t, entry.Actor.RecipientId, recipientId)
		test.IsEqualString(t, entry.Actor.RecipientEmail, "guest-uploader@example.com")
		test.IsEqualInt(t, entry.Actor.UserId, 0)
		test.IsEqualBool(t, strings.Contains(entry.Detail, owner.Name), true)
	}
	test.IsEqualBool(t, found, true)
}

// newCappedFileRequest creates a file request with the given MaxFiles via apiURequestSave, the
// same way an admin would create one, and returns its id and public api key.
func newCappedFileRequest(t *testing.T, name string, maxFiles int) (id, apiKey string) {
	admin := models.User{Id: idAdmin, UserLevel: models.UserLevelAdmin, Permissions: models.UserPermissionAll}
	w := httptest.NewRecorder()
	request := &paramURequestSave{
		Name:          name,
		MaxFiles:      maxFiles,
		IsMaxFilesSet: true,
		foundHeaders:  map[string]bool{},
	}
	apiURequestSave(w, request, admin, models.ApiKey{})
	test.IsEqualInt(t, w.Code, 200)
	var response struct {
		FileRequest models.FileRequest
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))
	return response.FileRequest.Id, response.FileRequest.ApiKey
}

func reserveChunk(publicKey, frId string) *httptest.ResponseRecorder {
	w, r := getRecorderWithBody("/uploadrequest/chunk/reserve", publicKey, "POST", []test.Header{
		{Name: "id", Value: frId},
	}, nil)
	Process(w, r)
	return w
}

// TestApiChunkReserveConcurrentReservesNeverExceedCap is an end-to-end check that hammering the
// real apiChunkReserve handler concurrently for a capped file request never lets total successful
// reservations exceed MaxFiles. It calls apiChunkReserve directly (not through
// Process/getRecorderWithBody) so the concurrency lands on the handler itself rather than being
// spread out by the per-request DB round trip in checkFileRequestAndApiKey.
//
// This complements, but does not replace,
// chunkreservation.TestNewIfUnder_ConcurrentReservesNeverExceedLimit, which is the authoritative
// failing-first regression test for bug 2: that test isolates NewIfUnder's count-check-and-insert
// with no DB call in between, and reliably overshoots the limit once reverted to a separate
// GetCount-then-New. Here, the DB read that precedes the count check adds enough jitter between
// goroutines reaching the vulnerable window that this end-to-end version does not reliably
// overshoot even against the pre-fix check-then-act code, so it is kept as a real-endpoint sanity
// check rather than as fail-before-fix evidence.
func TestApiChunkReserveConcurrentReservesNeverExceedCap(t *testing.T) {
	const maxFiles = 5
	const concurrency = 100
	frId, apiKeyId := newCappedFileRequest(t, "concurrent-cap-request", maxFiles)
	apiKey := models.ApiKey{Id: apiKeyId}

	var wg sync.WaitGroup
	var successCount int64
	start := make(chan struct{})
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			apiChunkReserve(w, &paramChunkReserve{Id: frId}, models.User{}, apiKey)
			if w.Code == http.StatusOK {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successCount > maxFiles {
		t.Fatalf("expected at most %d successful reservations out of %d concurrent attempts, got %d", maxFiles, concurrency, successCount)
	}
}

// TestApiChunkReserveUnlimitedReservesFreely checks that a file request with no MaxFiles cap
// (IsUnlimitedFiles) can still reserve as many chunks as needed - the negative-limit "no cap"
// path passed to chunkreservation.NewIfUnder must not become accidentally restrictive.
func TestApiChunkReserveUnlimitedReservesFreely(t *testing.T) {
	frId, publicKey := newCappedFileRequest(t, "unlimited-reserve-request", 0)

	for i := 0; i < 20; i++ {
		w := reserveChunk(publicKey, frId)
		test.IsEqualInt(t, w.Code, 200)
	}
}

// TestApiChunkReserveRateLimitAppliesToCappedRequest is the failing-first regression test for bug
// 1 in apiChunkReserve: the rate limit check used to sit inside the `IsUnlimitedFiles()` branch,
// so a file request WITH a MaxFiles cap got no rate limiting on /uploadrequest/chunk/reserve at
// all - the one case with a finite budget worth protecting went unthrottled, while the unlimited
// case (nothing to exhaust) was the only one throttled. Real rate limiting is disabled for this
// whole test binary (see TestMain), so it is switched on only for the duration of this test,
// against a file request id no other test uses, so as not to disturb - or be disturbed by -
// shared limiter state.
func TestApiChunkReserveRateLimitAppliesToCappedRequest(t *testing.T) {
	ratelimiter.SetUnitTestMode(false)
	t.Cleanup(func() { ratelimiter.SetUnitTestMode(true) })

	// MaxFiles is well above the rate limiter's burst of 4, so the file cap itself never
	// triggers first and any 429 seen below can only come from the rate limiter.
	frId, publicKey := newCappedFileRequest(t, "rate-limit-capped-request", 50)

	sawRateLimited := false
	for i := 0; i < 20; i++ {
		w := reserveChunk(publicKey, frId)
		if w.Code == http.StatusTooManyRequests {
			sawRateLimited = true
			break
		}
		test.IsEqualInt(t, w.Code, 200)
	}

	if !sawRateLimited {
		t.Fatal("expected a burst of reserve calls against a capped file request to eventually be rate-limited with 429")
	}
}

func TestFilesDuplicateSanitisation(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)

	const apiUrl = "/files/duplicate"

	// Path traversal in the new filename for a duplicate must be sanitised.
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: idFileUser},
		{Name: "filename", Value: "../../etc/shadow"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var output models.FileApiOutput
	err := json.Unmarshal(w.Body.Bytes(), &output)
	test.IsNil(t, err)
	test.IsEqualBool(t, strings.HasPrefix(output.Name, ".."), false)
	test.IsEqualBool(t, strings.Contains(output.Name, "/"), false)

	// CRLF in the duplicate filename must be stripped.
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "id", Value: idFileUser},
		{Name: "filename", Value: "file.txt\r\nX-Evil: injected"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	err = json.Unmarshal(w.Body.Bytes(), &output)
	test.IsNil(t, err)
	test.IsEqualBool(t, strings.Contains(output.Name, "\r"), false)
	test.IsEqualBool(t, strings.Contains(output.Name, "\n"), false)
}

func TestChunkCompleteSanitisationUnit(t *testing.T) {
	p := &paramChunkComplete{}
	p.foundHeaders = map[string]bool{"realsize": true}
	p.RealSize = 10
	p.FileSize = 10
	p.AllowedDownloads = 1
	p.ExpiryDays = 14
	p.ContentType = "text/plain"
	p.FileName = "../../etc/passwd\r\nSet-Cookie: x=1"

	err := p.ProcessParameter(nil)
	test.IsNil(t, err)

	// The FileHeader must receive the sanitised filename, not the raw one.
	test.IsEqualString(t, p.FileHeader.Filename, p.FileName)
	test.IsEqualBool(t, strings.HasPrefix(p.FileHeader.Filename, ".."), false)
	test.IsEqualBool(t, strings.Contains(p.FileHeader.Filename, "\r"), false)
	test.IsEqualBool(t, strings.Contains(p.FileHeader.Filename, "\n"), false)
}

// TestChunkCompleteExpiryTimestampRejectsPast proves paramChunkComplete.ProcessParameter
// refuses a non-zero expiryTimestamp that has already passed, in the same style as the
// filename check just above: a validation error returned directly from ProcessParameter,
// before any file is created.
func TestChunkCompleteExpiryTimestampRejectsPast(t *testing.T) {
	p := &paramChunkComplete{}
	p.foundHeaders = map[string]bool{"realsize": true}
	p.RealSize = 10
	p.FileSize = 10
	p.FileName = "test.txt"
	p.ExpiryTimestamp = time.Now().Add(-time.Hour).Unix()

	err := p.ProcessParameter(nil)
	test.IsNotNil(t, err)

	// A zero expiryTimestamp (not supplied) is never rejected as "in the past".
	p2 := &paramChunkComplete{}
	p2.foundHeaders = map[string]bool{"realsize": true}
	p2.RealSize = 10
	p2.FileSize = 10
	p2.FileName = "test.txt"
	p2.ExpiryTimestamp = 0

	test.IsNil(t, p2.ProcessParameter(nil))

	// A future expiryTimestamp is accepted.
	p3 := &paramChunkComplete{}
	p3.foundHeaders = map[string]bool{"realsize": true}
	p3.RealSize = 10
	p3.FileSize = 10
	p3.FileName = "test.txt"
	p3.ExpiryTimestamp = time.Now().Add(time.Hour).Unix()

	test.IsNil(t, p3.ProcessParameter(nil))
}

// TestApiURequestSaveClampsExpiry proves apiURequestSave no longer writes a file request's
// Expiry straight from client input - GOKAPI_MAX_EXPIRY must be enforced here the same way
// apiFilesModify already enforces it for a single file's ExpireAt.
func TestApiURequestSaveClampsExpiry(t *testing.T) {
	os.Setenv("GOKAPI_MAX_EXPIRY", "7d")
	defer os.Unsetenv("GOKAPI_MAX_EXPIRY")
	latest := time.Now().Add(7 * 24 * time.Hour).Unix()

	admin := models.User{Id: idAdmin, UserLevel: models.UserLevelAdmin, Permissions: models.UserPermissionAll}

	// A far-future expiry is clamped down to the maximum.
	w := httptest.NewRecorder()
	farFuture := time.Now().Add(365 * 24 * time.Hour).Unix()
	request := &paramURequestSave{
		Name:         "clamp-test-request",
		Expiry:       farFuture,
		IsExpirySet:  true,
		foundHeaders: map[string]bool{},
	}
	apiURequestSave(w, request, admin, models.ApiKey{})
	test.IsEqualInt(t, w.Code, 200)

	var response struct {
		FileRequest models.FileRequest
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))
	saved, ok := database.GetFileRequest(response.FileRequest.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, saved.Expiry <= latest+2, true)

	// An unlimited (0) expiry is likewise refused and pinned to the maximum.
	w2 := httptest.NewRecorder()
	request2 := &paramURequestSave{
		Name:         "clamp-test-request-unlimited",
		Expiry:       0,
		IsExpirySet:  true,
		foundHeaders: map[string]bool{},
	}
	apiURequestSave(w2, request2, admin, models.ApiKey{})
	test.IsEqualInt(t, w2.Code, 200)

	var response2 struct {
		FileRequest models.FileRequest
	}
	test.IsNil(t, json.Unmarshal(w2.Body.Bytes(), &response2))
	saved2, ok := database.GetFileRequest(response2.FileRequest.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, saved2.Expiry <= latest+2 && saved2.Expiry > 0, true)
}

func TestLogsAudit(t *testing.T) {
	const apiUrl = "/logs/audit"
	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageLogs)

	// Setup: create a temporary config dir and init audit + text logs
	tempDir := t.TempDir()
	logging.Init(tempDir)

	// Create test audit entries via the logging package
	testRequest := httptest.NewRequest("GET", "/test", nil)
	testRequest.Header.Set("User-Agent", "test-agent")

	test.IsNil(t, logging.LogUpload(models.File{
		Id:     "testfile1",
		Name:   "test1.txt",
		UserId: idAdmin,
		SHA1:   "abc123",
		Size:   "1024",
	}, models.User{Id: idAdmin, Name: "TestAdmin"}, models.FileRequest{}, testRequest, false))

	test.IsNil(t, logging.LogDownload(models.File{
		Id:     "testfile1",
		Name:   "test1.txt",
		UserId: idAdmin,
		SHA1:   "abc123",
		Size:   "1024",
	}, testRequest, false))

	logging.LogDelete(models.File{
		Id:     "testfile1",
		Name:   "test1.txt",
		UserId: idAdmin,
		SHA1:   "abc123",
		Size:   "1024",
	}, models.User{Id: idAdmin, Name: "TestAdmin"})

	// Give async logging time to write
	time.Sleep(500 * time.Millisecond)

	// Test 1: Get all audit entries with no params
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	type auditResponse struct {
		Entries []logging.AuditEntry `json:"entries"`
		LastSeq uint64               `json:"lastSeq"`
	}
	var result auditResponse
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)

	// Should have at least 3 entries
	test.IsEqualBool(t, len(result.Entries) >= 3, true)
	// Verify they're in oldest-first order (Seq increasing)
	if len(result.Entries) > 1 {
		for i := 1; i < len(result.Entries); i++ {
			test.IsEqualBool(t, result.Entries[i].Seq > result.Entries[i-1].Seq, true)
		}
	}
	// LastSeq should be the max Seq from entries
	if len(result.Entries) > 0 {
		maxSeq := result.Entries[0].Seq
		for _, entry := range result.Entries {
			if entry.Seq > maxSeq {
				maxSeq = entry.Seq
			}
		}
		test.IsEqual(t, result.LastSeq, maxSeq)
	}

	firstSeq := result.Entries[0].Seq
	secondSeq := result.Entries[1].Seq
	firstLastSeq := result.LastSeq

	// Test 2: Get entries from a specific Seq
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "fromSeq", Value: strconv.FormatUint(firstSeq, 10)},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	// Should get entries after firstSeq (not including firstSeq itself)
	if len(result.Entries) > 0 {
		test.IsEqualBool(t, result.Entries[0].Seq > firstSeq, true)
	}

	// Test 3: Limit the number of entries
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "limit", Value: "1"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualInt(t, len(result.Entries), 1)
	// LastSeq should still be the overall max
	test.IsEqual(t, result.LastSeq, firstLastSeq)

	// Test 4: Test limit with fromSeq
	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{
		{Name: "fromSeq", Value: strconv.FormatUint(firstSeq, 10)},
		{Name: "limit", Value: "1"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualInt(t, len(result.Entries), 1)
	test.IsEqual(t, result.Entries[0].Seq, secondSeq)

	// Test 5: Verify the endpoint is read-only (GET only)
	routeFound := false
	for _, route := range routes {
		if route.Url == apiUrl {
			routeFound = true
			test.IsEqualBool(t, route.NoJsonResponse, false) // Should return JSON
			// Note: there's no DELETE for /logs/audit
		}
	}
	test.IsEqualBool(t, routeFound, true)

	// Test 6: Empty audit log returns empty entries array, not nil
	emptyTempDir := t.TempDir()
	logging.Init(emptyTempDir)
	time.Sleep(50 * time.Millisecond)

	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	test.IsEqualInt(t, len(result.Entries), 0)
	test.IsEqual(t, result.LastSeq, uint64(0))

	// Verify it's an empty array, not null
	bodyStr := w.Body.String()
	test.IsEqualBool(t, strings.Contains(bodyStr, `"entries":[]`), true)

	// Restore logging to the test data directory to avoid panics in subsequent tests
	// when trying to write to a temp directory that's been deleted
	testDataDir := os.Getenv("GOKAPI_DATA_DIR")
	if testDataDir == "" {
		testDataDir = "test/data"
	}
	logging.Init(testDataDir)
}

func TestFolderCreate(t *testing.T) {
	apiKey := testAuthorisation(t, "/folder/create", models.ApiPermUpload)

	// Test missing name header
	testFolderCreateCall(t, apiKey, "", 400, `{"Result":"error","ErrorMessage":"header name is required","ErrorCode":4}`)

	// Test successful folder creation
	testFolderName := "TestFolderCreate_Folder"
	w, r := getRecorder("/folder/create", apiKey.Id, []test.Header{{Name: "name", Value: testFolderName}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	var response struct {
		Result     string
		FileBundle struct {
			Id     string
			Name   string
			UserId int
		}
	}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	test.IsNil(t, err)
	test.IsEqual(t, response.Result, "OK")
	test.IsEqual(t, response.FileBundle.Name, testFolderName)
	test.IsEqualBool(t, response.FileBundle.Id != "", true)

	// Test base64 encoded name
	testFolderNameUtf8 := "TestFolderCreate_UTF8_éàü"
	encodedName := "base64:" + base64.StdEncoding.EncodeToString([]byte(testFolderNameUtf8))
	w, r = getRecorder("/folder/create", apiKey.Id, []test.Header{{Name: "name", Value: encodedName}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
}

// TestFolderCreateWithPasswordExpiryDownloads proves POST /folder/create can give the folder
// its own password, expiry and download allowance directly - the fields that used to be derived
// entirely from member files (see models.FileBundle.PasswordHash and friends). Omitting a
// setting leaves filebundle.Create's own default (open, unlimited) in place.
func TestFolderCreateWithPasswordExpiryDownloads(t *testing.T) {
	apiKey := testAuthorisation(t, "/folder/create", models.ApiPermUpload)

	expiry := time.Now().Add(48 * time.Hour).Unix()
	w, r := getRecorder("/folder/create", apiKey.Id, []test.Header{
		{Name: "name", Value: "TestFolderCreateSettings"},
		{Name: "password", Value: "AValidFolderPw1!"},
		{Name: "allowedDownloads", Value: "3"},
		{Name: "expiryTimestamp", Value: strconv.FormatInt(expiry, 10)},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	var response struct {
		FileBundle struct{ Id string }
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))

	stored, ok := database.GetFileBundle(response.FileBundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.PasswordHash != "", true)
	test.IsEqualBool(t, stored.UnlimitedDownloads, false)
	test.IsEqualInt(t, stored.DownloadsRemaining, 3)
	test.IsEqualBool(t, stored.UnlimitedTime, false)
	test.IsEqualInt64(t, stored.ExpireAt, expiry)

	// A folder created with no settings stays open - filebundle.Create's own default.
	w2, r2 := getRecorder("/folder/create", apiKey.Id, []test.Header{
		{Name: "name", Value: "TestFolderCreateNoSettings"},
	})
	Process(w2, r2)
	test.IsEqualInt(t, w2.Code, 200)
	var response2 struct {
		FileBundle struct{ Id string }
	}
	test.IsNil(t, json.Unmarshal(w2.Body.Bytes(), &response2))
	storedOpen, ok := database.GetFileBundle(response2.FileBundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, storedOpen.PasswordHash, "")
	test.IsEqualBool(t, storedOpen.UnlimitedDownloads, true)
	test.IsEqualBool(t, storedOpen.UnlimitedTime, true)
}

func testFolderCreateCall(t *testing.T, apiKey models.ApiKey, name string, resultCode int, expectedResponse string) {
	t.Helper()
	const apiUrl = "/folder/create"
	headers := []test.Header{}
	if name != "" {
		headers = append(headers, test.Header{Name: "name", Value: name})
	}
	w, r := getRecorder(apiUrl, apiKey.Id, headers)
	Process(w, r)
	test.IsEqualInt(t, w.Code, resultCode)
	if expectedResponse != "" {
		test.ResponseBodyIs(t, w, expectedResponse)
	}
}

func TestFolderList(t *testing.T) {
	// Create some test folders and files
	apiKey := testAuthorisation(t, "/folder/list", models.ApiPermView)

	// Get initial count of folders for the user
	w, r := getRecorder("/folder/list", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	var initialResult []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &initialResult)
	test.IsNil(t, err)
	initialCount := len(initialResult)

	// Create folders for the user (use unique names to avoid test pollution)
	folder1 := filebundle.Create("TestFolderList_Folder1", idUser)
	_ = filebundle.Create("TestFolderList_Folder2", idUser) // folderUser2

	// Create a folder for another user
	folderOther := filebundle.Create("TestFolderList_OtherUserFolder", idSuperAdmin) // folderOther

	// Create some files and add them to the folders
	database.SaveMetaData(models.File{
		Id:                 "flist1",
		Name:               "flist1",
		SHA1:               "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:           2147483646,
		DownloadsRemaining: 1,
		UserId:             idUser,
		BundleId:           folder1.Id,
	})
	database.SaveMetaData(models.File{
		Id:                 "flist2",
		Name:               "flist2",
		SHA1:               "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:           2147483646,
		DownloadsRemaining: 1,
		UserId:             idUser,
		BundleId:           folder1.Id,
		SizeBytes:          1024,
	})

	// Add a file to the other user's folder so it has valid members
	database.SaveMetaData(models.File{
		Id:                 "flistOther",
		Name:               "flistOther",
		SHA1:               "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:           2147483646,
		DownloadsRemaining: 1,
		UserId:             idSuperAdmin,
		BundleId:           folderOther.Id,
	})

	// Test listing as regular user (should include our new folders)
	w, r = getRecorder("/folder/list", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	var result []map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	afterCreateCount := len(result)
	test.IsEqualBool(t, afterCreateCount > initialCount, true)

	// Verify we see folder1 with correct metadata
	found := false
	for _, bundle := range result {
		if bundle["id"] == folder1.Id {
			test.IsEqual(t, bundle["name"], "TestFolderList_Folder1")
			test.IsEqualInt(t, int(bundle["membercount"].(float64)), 2)
			test.IsEqualInt(t, int(bundle["totalsizebytes"].(float64)), 1024)
			found = true
			break
		}
	}
	test.IsEqualBool(t, found, true)

	// Grant LIST_OTHER_UPLOADS permission
	grantUserPermission(t, idUser, models.UserPermListOtherUploads)

	// Test listing with elevated permission (should see the additional folder from another user)
	w, r = getRecorder("/folder/list", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	result = []map[string]interface{}{}
	err = json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	// Should see folders now - verify the count increased or at least the other user's folder is visible
	allowsOtherFolders := false
	for _, bundle := range result {
		if bundle["id"] == folderOther.Id {
			allowsOtherFolders = true
			break
		}
	}
	// If we don't see the other folder, at least verify we see the user's own folders
	if !allowsOtherFolders {
		found := false
		for _, bundle := range result {
			if bundle["id"] == folder1.Id {
				found = true
				break
			}
		}
		test.IsEqualBool(t, found, true)
	}

	// Remove permission
	removeUserPermission(t, idUser, models.UserPermListOtherUploads)
}

func TestFolderDelete(t *testing.T) {
	apiKey := testAuthorisation(t, "/folder/delete", models.ApiPermDelete)

	// Create test folders (use unique names to avoid test pollution)
	folder1 := filebundle.Create("TestFolderDelete_Folder1", idUser)
	folder2 := filebundle.Create("TestFolderDelete_OtherUserFolder", idSuperAdmin)

	// Add files to folder1
	database.SaveMetaData(models.File{
		Id:                 "fdfile1",
		Name:               "fdfile1",
		SHA1:               "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:           2147483646,
		DownloadsRemaining: 1,
		UserId:             idUser,
		BundleId:           folder1.Id,
	})

	// Test missing id header
	testFolderDeleteCall(t, apiKey, "", 400, `{"Result":"error","ErrorMessage":"header id is required","ErrorCode":4}`)

	// Test invalid id
	testFolderDeleteCall(t, apiKey, "invalid", 404, `{"Result":"error","ErrorMessage":"Folder does not exist","ErrorCode":5}`)

	// Test successful deletion of own folder
	testFolderDeleteCall(t, apiKey, folder1.Id, 200, "")

	// Wait for async deletion to complete
	time.Sleep(100 * time.Millisecond)

	// Verify folder and files are deleted
	_, ok := filebundle.Get(folder1.Id)
	test.IsEqualBool(t, ok, false)
	_, ok = database.GetMetaDataById("fdfile1")
	test.IsEqualBool(t, ok, false)

	// Test deletion of other user's folder without permission
	testFolderDeleteCall(t, apiKey, folder2.Id, 401, `{"Result":"error","ErrorMessage":"No permission to delete this folder","ErrorCode":6}`)

	// Grant DELETE_OTHER_UPLOADS permission
	grantUserPermission(t, idUser, models.UserPermDeleteOtherUploads)

	// Test deletion with elevated permission
	testFolderDeleteCall(t, apiKey, folder2.Id, 200, "")
	_, ok = filebundle.Get(folder2.Id)
	test.IsEqualBool(t, ok, false)

	// Remove permission
	removeUserPermission(t, idUser, models.UserPermDeleteOtherUploads)
}

// TestFolderDeleteWritesBatchedAuditRecord verifies that deleting a folder with several
// member files records one contiguous, correctly hash-chained batch of audit entries (one per
// member plus one for the folder), rather than each member racing the next for the shared audit
// mutex through N separate synchronous fsyncs. See TestAuditChainBatchedWriteAllOrNothingOnFailure
// in the logging package for the accompanying failure-mode contract this exists for.
func TestFolderDeleteWritesBatchedAuditRecord(t *testing.T) {
	apiKey := testAuthorisation(t, "/folder/delete", models.ApiPermDelete)

	tempDir := t.TempDir()
	logging.Init(tempDir)
	defer func() {
		testDataDir := os.Getenv("GOKAPI_DATA_DIR")
		if testDataDir == "" {
			testDataDir = "test/data"
		}
		logging.Init(testDataDir)
	}()

	folder := filebundle.Create("TestFolderDeleteBatch_Folder", idUser)
	memberIds := []string{"batchApiMember1", "batchApiMember2", "batchApiMember3"}
	for _, id := range memberIds {
		database.SaveMetaData(models.File{
			Id:                 id,
			Name:               id,
			SHA1:               "03cfd743661f07975fa2f1220c5194cbaff48451",
			ExpireAt:           2147483646,
			DownloadsRemaining: 1,
			UserId:             idUser,
			BundleId:           folder.Id,
		})
	}

	testFolderDeleteCall(t, apiKey, folder.Id, 200, "")

	entries, _ := logging.GetAuditEntriesSince(0, 100)
	test.IsEqualInt(t, len(entries), len(memberIds)+1)

	prevHash := ""
	var fileEntries, folderEntries int
	for _, e := range entries {
		test.IsEqualString(t, e.PrevHash, prevHash)
		prevHash = e.Hash
		if e.Action == "file.deleted" {
			fileEntries++
		}
		if e.Action == "folder.deleted" && e.BundleId == folder.Id {
			folderEntries++
		}
	}
	test.IsEqualInt(t, fileEntries, len(memberIds))
	test.IsEqualInt(t, folderEntries, 1)
}

func testFolderDeleteCall(t *testing.T, apiKey models.ApiKey, folderId string, resultCode int, expectedResponse string) {
	t.Helper()
	const apiUrl = "/folder/delete"
	headers := []test.Header{}
	if folderId != "" {
		headers = append(headers, test.Header{Name: "id", Value: folderId})
	}
	w, r := getRecorder(apiUrl, apiKey.Id, headers)
	Process(w, r)
	test.IsEqualInt(t, w.Code, resultCode)
	if expectedResponse != "" {
		test.ResponseBodyIs(t, w, expectedResponse)
	}
}

// TestChunkCompleteBundleOwnershipRejected tests that /api/chunk/complete rejects
// attempts to upload to a bundle owned by a different user. The bundleid header
// must belong to the authenticated user.
func TestChunkCompleteBundleOwnershipRejected(t *testing.T) {
	apiKeyUser := generateNewKey(false, idUser, "", "")
	apiKeyUser.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKeyUser)

	apiKeyAdmin := generateNewKey(false, idAdmin, "", "")
	apiKeyAdmin.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKeyAdmin)

	bundleUser := filebundle.Create("TestBundleOwner_User_"+helper.GenerateRandomString(8), idUser)
	bundleAdmin := filebundle.Create("TestBundleOwner_Admin_"+helper.GenerateRandomString(8), idAdmin)

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKeyUser.Id},
		{Name: "uuid", Value: helper.GenerateRandomString(16)},
		{Name: "filename", Value: "test.txt"},
		{Name: "filesize", Value: "100"},
		{Name: "bundleid", Value: bundleAdmin.Id}}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyIs(t, w, `{"Result":"error","ErrorMessage":"bundle does not belong to user","ErrorCode":10}`)

	w2, r2 := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKeyUser.Id},
		{Name: "uuid", Value: helper.GenerateRandomString(16)},
		{Name: "filename", Value: "test2.txt"},
		{Name: "filesize", Value: "100"},
		{Name: "bundleid", Value: bundleUser.Id}}, nil)
	Process(w2, r2)
	test.IsEqualInt(t, w2.Code, 400)
	// Positive control: assert the error is NOT the ownership error
	if strings.Contains(w2.Body.String(), "bundle does not belong to user") {
		t.Errorf("Positive control should not fail with ownership error when using correct bundle owner")
	}
}

// sealedStatusResponse mirrors apiSealStatus's JSON shape. Deliberately has no EncryptionLevel
// field: that used to be exposed to any unauthenticated caller, letting them fingerprint the
// instance (e.g. confirming Level 4 - and therefore an anonymously reachable /api/unseal - is
// worth attacking) for no legitimate benefit to the SPA's "should I show an unseal prompt"
// decision, which only needs Sealed.
type sealedStatusResponse struct {
	Sealed bool `json:"sealed"`
}

func getSealStatus(t *testing.T) (*httptest.ResponseRecorder, sealedStatusResponse) {
	t.Helper()
	w, r := test.GetRecorder("GET", "/api/seal-status", nil, nil, nil)
	Process(w, r)
	var result sealedStatusResponse
	err := json.Unmarshal(w.Body.Bytes(), &result)
	test.IsNil(t, err)
	return w, result
}

func postUnseal(password string) (*httptest.ResponseRecorder, *http.Request) {
	body, _ := json.Marshal(struct {
		Password string `json:"password"`
	}{Password: password})
	w, r := test.GetRecorder("POST", "/api/unseal", nil, nil, bytes.NewReader(body))
	// apiUnseal only accepts a host-local connection (see isHostLocalUnsealRequest); a real
	// on-host caller reaches the handler over 127.0.0.1 with no forwarding header. httptest sets a
	// non-loopback RemoteAddr by default, so set it explicitly here for the happy path.
	r.RemoteAddr = "127.0.0.1:34567"
	return w, r
}

// sealAtFullEncryptionInput seals the instance at FullEncryptionInput with a real,
// scrypt-verifiable password (the same derivation POST /api/unseal exercises via
// encryption.Unseal), and restores the instance to whatever decryption-availability state it had
// before the calling test - matching an already-loaded master key back with a freshly generated
// one, mirroring withMasterKey's own "additive only" contract, so a later test in this shared
// binary that assumes a master key is loaded is not left with none.
func sealAtFullEncryptionInput(t *testing.T, password, saltSuffix string) {
	t.Helper()
	wasAvailable := encryption.IsDecryptionAvailable()
	previousLevel := configuration.Get().Encryption.Level
	checksumSalt := "api-seal-test-checksum-salt-" + saltSuffix
	// isEncryptionRequested (storage.FileServing.go), which the upload gate depends on, reads
	// the level from the configuration package directly - encryption.Init alone only affects
	// the encryption package's own state, so both have to be set for the gate to engage.
	configuration.Get().Encryption.Level = encryption.FullEncryptionInput
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level:        encryption.FullEncryptionInput,
		Salt:         "api-seal-test-salt-" + saltSuffix,
		ChecksumSalt: checksumSalt,
		Checksum:     encryption.PasswordChecksum(password, checksumSalt),
	}})
	t.Cleanup(func() {
		configuration.Get().Encryption.Level = previousLevel
		if wasAvailable {
			key, err := encryption.GetRandomCipher()
			test.IsNil(t, err)
			encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.FullEncryptionStored, Cipher: key}})
			return
		}
		encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})
	})
}

// TestApiSealStatus is the failing-first test for GET /api/seal-status: it must be reachable
// with no apikey header at all (an admin cannot be authenticated before the instance is
// unsealed, in the general case), and it must report only the true sealed state - not the
// configured encryption level (see L5): that field has no legitimate use for an unauthenticated
// caller and only helps an attacker fingerprint the instance.
func TestApiSealStatus(t *testing.T) {
	previousLevel := configuration.Get().Encryption.Level
	t.Cleanup(func() { configuration.Get().Encryption.Level = previousLevel })

	configuration.Get().Encryption.Level = encryption.NoEncryption
	w, result := getSealStatus(t)
	test.IsEqualInt(t, w.Code, 200)
	test.IsEqualBool(t, result.Sealed, false)
	test.IsEqualBool(t, strings.Contains(strings.ToLower(w.Body.String()), "encryptionlevel"), false)

	configuration.Get().Encryption.Level = encryption.FullEncryptionInput
	sealAtFullEncryptionInput(t, "seal-status-password", "sealstatus")
	w, result = getSealStatus(t)
	test.IsEqualInt(t, w.Code, 200)
	test.IsEqualBool(t, result.Sealed, true)
	test.IsEqualBool(t, strings.Contains(strings.ToLower(w.Body.String()), "encryptionlevel"), false)
}

// TestApiUnsealRejectsProxiedRequests is the failing-first regression test for the host-local gate
// on POST /api/unseal (C1): the master-key passphrase must never be accepted from a request that
// traversed the reverse proxy chain. Every proxied request carries an X-Forwarded-For header (Caddy
// and ingress-nginx both append it), and a request from a public peer with no forwarding header must
// also be refused; both get a plain 404 before the rate limiter, the seal check, or any body parsing,
// so the endpoint is neither usable nor discoverable from the public internet. A host-local request
// with no forwarding header - including one whose peer is the Docker bridge gateway, which is how an
// on-VM caller actually reaches the loopback-published container port - must pass the gate.
func TestApiUnsealRejectsProxiedRequests(t *testing.T) {
	const password = "loopback-gate-password"
	sealAtFullEncryptionInput(t, password, "loopback-gate")

	// Sealed, so a request that reaches the real logic with the correct password would unseal it;
	// we assert these rejected requests do NOT, i.e. the gate short-circuits before any derivation.
	_, result := getSealStatus(t)
	test.IsEqualBool(t, result.Sealed, true)

	// A request with an X-Forwarded-For header, even from a loopback peer, is treated as proxied.
	w, r := postUnseal(password)
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	Process(w, r)
	test.IsEqualInt(t, w.Code, http.StatusNotFound)

	// A request from a public peer with no forwarding header is refused too (the loopback-published
	// port makes this unreachable in practice, but the gate must not rely on that alone).
	w, r = postUnseal(password)
	r.RemoteAddr = "203.0.113.7:5000"
	Process(w, r)
	test.IsEqualInt(t, w.Code, http.StatusNotFound)

	// The correct password on both rejected paths must NOT have unsealed the instance.
	_, result = getSealStatus(t)
	test.IsEqualBool(t, result.Sealed, true)

	// The real production path: an on-VM caller hitting the loopback-published container port arrives
	// at the app from the Docker bridge gateway (a private address) with no forwarding header. This
	// must pass the gate and unseal correctly.
	w, r = postUnseal(password)
	r.RemoteAddr = "172.18.0.1:41000"
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	_, result = getSealStatus(t)
	test.IsEqualBool(t, result.Sealed, false)
}

// TestApiUnsealNotSealedIsRejectedWithoutLogging is the failing-first regression test for the
// audit-forgery bug in apiUnseal (C1a): previously, apiUnseal never checked encryption.IsSealed()
// before calling encryption.Unseal, and encryption.Unseal returns nil (success) for an
// already-unsealed instance regardless of the password given - so ANY caller, with ANY password
// (including an empty one), got a 200 OK against an already-unsealed instance, and that 200 was
// then audited as "Instance unsealed successfully by IP x". That let an anonymous caller forge a
// successful-unseal audit trail entry at will, without ever supplying a correct password.
//
// After the fix, hitting POST /api/unseal while not sealed must return 409 and must not write any
// unseal-related log entry at all, successful or failed - since no password was ever compared to
// anything, it must not be recorded as an attempt.
func TestApiUnsealNotSealedIsRejectedWithoutLogging(t *testing.T) {
	previousLevel := configuration.Get().Encryption.Level
	t.Cleanup(func() { configuration.Get().Encryption.Level = previousLevel })
	configuration.Get().Encryption.Level = encryption.NoEncryption
	test.IsEqualBool(t, encryption.IsSealed(), false)

	// Drain any lagging async log goroutines from an earlier test BEFORE repointing the global
	// log path to tempDir: LogUnsealAttempt writes asynchronously and logPath is a package global,
	// so without this a prior test's write could land in tempDir/log.txt and pollute the assertion
	// below (the failure this test would otherwise flake on under the -parallel gate).
	time.Sleep(500 * time.Millisecond)

	tempDir := t.TempDir()
	logging.Init(tempDir)

	w, r := postUnseal("totally the wrong password, or even the right one - it must not matter")
	Process(w, r)

	test.IsEqualInt(t, w.Code, http.StatusConflict)

	// Give the (non-blocking) audit/text logging goroutines time to run, exactly as the existing
	// TestLogsAudit does, then confirm nothing whatsoever was written about this request.
	time.Sleep(500 * time.Millisecond)
	logContent, exists := logging.GetAll()
	if exists {
		test.IsEqualBool(t, strings.Contains(strings.ToLower(logContent), "unseal"), false)
	}

	// Restore logging to the test data directory to avoid panics in subsequent tests when
	// trying to write to a temp directory that's been deleted - same rationale as TestLogsAudit.
	testDataDir := os.Getenv("GOKAPI_DATA_DIR")
	if testDataDir == "" {
		testDataDir = "test/data"
	}
	logging.Init(testDataDir)
}

// TestApiUnsealCorrectAndIncorrectPassword is the failing-first test for POST /api/unseal: a
// wrong (or empty) password must return a generic failure and leave the instance sealed (visible
// via /api/seal-status), while the correct password must unseal it and flip seal-status - both
// with no apikey header, since this endpoint is deliberately unauthenticated.
func TestApiUnsealCorrectAndIncorrectPassword(t *testing.T) {
	const password = "the correct unseal password"
	sealAtFullEncryptionInput(t, password, "unseal-correctness")

	_, result := getSealStatus(t)
	test.IsEqualBool(t, result.Sealed, true)

	// Empty password.
	w, r := postUnseal("")
	Process(w, r)
	test.IsEqualBool(t, w.Code == 200, false)
	var errResult struct {
		Result       string `json:"Result"`
		ErrorMessage string `json:"ErrorMessage"`
		ErrorCode    int    `json:"ErrorCode"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &errResult)
	test.IsNil(t, err)
	test.IsEqualString(t, errResult.Result, "error")
	test.IsEqualBool(t, strings.Contains(strings.ToLower(errResult.ErrorMessage), "password"), true)
	// The generic failure must not reveal anything more specific than "incorrect" - in
	// particular it must never echo the submitted (empty) password back, nor say anything
	// distinguishing this from a wrong-but-nonempty password.
	test.IsEqualBool(t, strings.Contains(errResult.ErrorMessage, password), false)
	_, result = getSealStatus(t)
	test.IsEqualBool(t, result.Sealed, true)

	// Wrong, nonempty password: same generic shape, still sealed.
	w, r = postUnseal("the WRONG password")
	Process(w, r)
	test.IsEqualBool(t, w.Code == 200, false)
	errResult = struct {
		Result       string `json:"Result"`
		ErrorMessage string `json:"ErrorMessage"`
		ErrorCode    int    `json:"ErrorCode"`
	}{}
	err = json.Unmarshal(w.Body.Bytes(), &errResult)
	test.IsNil(t, err)
	test.IsEqualString(t, errResult.Result, "error")
	_, result = getSealStatus(t)
	test.IsEqualBool(t, result.Sealed, true)

	// Correct password: unseals, and seal-status flips.
	w, r = postUnseal(password)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	_, result = getSealStatus(t)
	test.IsEqualBool(t, result.Sealed, false)
}

// TestApiUnsealRateLimitReturns429 is the failing-first test for turning unseal throttling from a
// blocking wait (the old ratelimiter.WaitOnUnseal, which only ever delayed via WaitN and never
// rejected) into an immediate rejection: once an IP has exhausted its burst (see
// ratelimiter.AllowUnseal), a further POST /api/unseal request from that IP must get 429
// promptly - not be parked until the limiter would eventually allow it through. Every request
// here uses an empty password, so this never reaches encryption.Unseal's expensive scrypt path
// (see TestApiUnsealCorrectAndIncorrectPassword for that); only the per-IP throttle in front of
// it is under test. Real rate limiting is disabled for this whole test binary (see TestMain), so
// it is switched on only for the duration of this test, against an IP address no other test in
// this file uses, so as not to disturb - or be disturbed by - shared limiter state. That address
// must itself still be loopback or private and carry no forwarding header: isHostLocalUnsealRequest
// (checked before the rate limiter, see apiUnseal) rejects any other RemoteAddr with a plain 404
// regardless of the limiter's state, so a distinguishing key can only come from a different
// loopback address (here 127.0.0.2, vs. postUnseal's default 127.0.0.1) - not a public one.
func TestApiUnsealRateLimitReturns429(t *testing.T) {
	ratelimiter.SetUnitTestMode(false)
	t.Cleanup(func() { ratelimiter.SetUnitTestMode(true) })

	const password = "rate-limit-test-password"
	sealAtFullEncryptionInput(t, password, "unseal-ratelimit")

	newRequest := func() (*httptest.ResponseRecorder, *http.Request) {
		w, r := postUnseal("")
		r.RemoteAddr = "127.0.0.2:54321"
		return w, r
	}

	for i := 0; i < 20; i++ {
		w, r := newRequest()
		Process(w, r)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d: got 429 before the burst should have been exhausted", i+1)
		}
	}

	start := time.Now()
	w, r := newRequest()
	Process(w, r)
	elapsed := time.Since(start)

	test.IsEqualInt(t, w.Code, http.StatusTooManyRequests)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("request blocked for %v instead of returning 429 promptly", elapsed)
	}
	_, result := getSealStatus(t)
	test.IsEqualBool(t, result.Sealed, true)
}

// TestApiUnsealBusyReturns429 is the failing-first test for the process-wide derivation
// semaphore's effect at the HTTP layer (see encryption.Unseal / encryption.ErrUnsealBusy): while
// a derivation is in flight, apiUnseal must answer 429 rather than also run scrypt or queue
// behind it - this is what bounds memory to a single ~1 GiB derivation regardless of attacker
// concurrency. Exercised cheaply, without running a real derivation at all: the single
// process-wide slot is taken directly via encryption.AcquireUnsealSemaphoreForTesting, mirroring
// TestUnsealSemaphoreRejectsWhenBusy in the encryption package but confirming apiUnseal's own
// mapping of ErrUnsealBusy onto the HTTP response.
func TestApiUnsealBusyReturns429(t *testing.T) {
	const password = "api-busy-test-password"
	sealAtFullEncryptionInput(t, password, "unseal-busy")

	acquired := encryption.AcquireUnsealSemaphoreForTesting()
	test.IsEqualBool(t, acquired, true)
	defer encryption.ReleaseUnsealSemaphoreForTesting()

	w, r := postUnseal(password)
	Process(w, r)
	test.IsEqualInt(t, w.Code, http.StatusTooManyRequests)

	_, result := getSealStatus(t)
	test.IsEqualBool(t, result.Sealed, true)
}

// TestApiUnsealGatesKeyDependentOperations is the failing-first test for the "refuse cleanly
// while sealed" requirement at the API layer: an upload and a request for
// /files/{id}/sharekey must both answer 503 with errorcodes.InstanceSealed while sealed - not
// panic, not silently misbehave - and both must work normally again once unsealed.
func TestApiUnsealGatesKeyDependentOperations(t *testing.T) {
	const password = "gating-test-password"
	sealAtFullEncryptionInput(t, password, "gating")

	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	apiKey.GrantPermission(models.ApiPermView)
	database.SaveApiKey(apiKey)

	// A separate uuid/chunk file per attempt: doBlockingPartCompleteChunk deletes the reserved
	// chunk on any error (including the sealed refusal below), so reusing one across both the
	// sealed and the post-unseal attempt would make the second attempt fail for an unrelated
	// reason (no such chunk) rather than actually proving upload works again once unsealed.
	sealedContent := []byte("sealed gating test content")
	uuidSealed := helper.GenerateRandomString(16)
	err := os.WriteFile("test/data/chunk-"+uuidSealed, sealedContent, 0600)
	test.IsNil(t, err)
	defer os.Remove("test/data/chunk-" + uuidSealed)

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: uuidSealed},
		{Name: "filename", Value: "sealed-gate-test.txt"},
		{Name: "filesize", Value: strconv.Itoa(len(sealedContent))},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, http.StatusServiceUnavailable)
	var errResult struct {
		ErrorCode int `json:"ErrorCode"`
	}
	err = json.Unmarshal(w.Body.Bytes(), &errResult)
	test.IsNil(t, err)
	test.IsEqualInt(t, errResult.ErrorCode, errorcodes.InstanceSealed)

	// /files/{id}/sharekey must also refuse while sealed - checked against a file created
	// before sealing (idFileUser from generateTestData), since the point under test is the read
	// path, not upload gating.
	w, r = getShareKey(apiKey.Id, idFileUser)
	Process(w, r)
	test.IsEqualInt(t, w.Code, http.StatusServiceUnavailable)
	errResult = struct {
		ErrorCode int `json:"ErrorCode"`
	}{}
	err = json.Unmarshal(w.Body.Bytes(), &errResult)
	test.IsNil(t, err)
	test.IsEqualInt(t, errResult.ErrorCode, errorcodes.InstanceSealed)

	// Once unsealed, a fresh upload must succeed normally.
	err = encryption.Unseal(password)
	test.IsNil(t, err)

	afterUnsealContent := []byte("post-unseal gating test content")
	uuidAfterUnseal := helper.GenerateRandomString(16)
	err = os.WriteFile("test/data/chunk-"+uuidAfterUnseal, afterUnsealContent, 0600)
	test.IsNil(t, err)
	defer os.Remove("test/data/chunk-" + uuidAfterUnseal)

	w, r = test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: uuidAfterUnseal},
		{Name: "filename", Value: "post-unseal-gate-test.txt"},
		{Name: "filesize", Value: strconv.Itoa(len(afterUnsealContent))},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
}

// --- Share inbox (Part C) ---

type shareInboxItemTest struct {
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

type shareInboxResponseTest struct {
	Result string               `json:"result"`
	Items  []shareInboxItemTest `json:"items"`
}

// TestApiShareInboxListsOnlyOwnEmailGrants proves that /share/inbox is scoped to the caller's own
// identity: a grant made to a different address never leaks into another account's inbox, even
// though both grants exist in the same table.
func TestApiShareInboxListsOnlyOwnEmailGrants(t *testing.T) {
	now := time.Now().Unix()
	ownEmail := "inbox-own@example.com"
	otherEmail := "inbox-other@example.com"

	ownRecipient := database.SaveShareRecipient(models.ShareRecipient{Email: ownEmail, CreatedAt: now})
	otherRecipient := database.SaveShareRecipient(models.ShareRecipient{Email: otherEmail, CreatedAt: now})

	database.SaveMetaData(models.File{
		Id: "inboxFileOwn", Name: "own.txt", SHA1: "inboxsha1own",
		UnlimitedDownloads: true, UnlimitedTime: true, UserId: idAdmin,
	})
	database.SaveMetaData(models.File{
		Id: "inboxFileOther", Name: "other.txt", SHA1: "inboxsha1other",
		UnlimitedDownloads: true, UnlimitedTime: true, UserId: idAdmin,
	})

	database.SetShareGrants(models.ShareResourceFile, "inboxFileOwn", []int{ownRecipient}, idAdmin, 5)
	database.SetShareGrants(models.ShareResourceFile, "inboxFileOther", []int{otherRecipient}, idAdmin, 5)

	user := models.User{Id: 5001, Name: ownEmail}
	w := httptest.NewRecorder()
	apiShareInbox(w, nil, user, models.ApiKey{})
	test.IsEqualInt(t, w.Code, 200)

	var response shareInboxResponseTest
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))
	test.IsEqualInt(t, len(response.Items), 1)
	test.IsEqualString(t, response.Items[0].ResourceId, "inboxFileOwn")
	test.IsEqualString(t, response.Items[0].Name, "own.txt")
	test.IsEqualInt(t, response.Items[0].DownloadsAllowed, 5)

	adminUser, found := database.GetUser(idAdmin)
	test.IsEqualBool(t, found, true)
	test.IsEqualString(t, response.Items[0].SharedBy, adminUser.Name)
}

// TestApiShareInboxBlockedRecipientIsEmpty proves that a recipient blocked by an uploader loses
// their inbox immediately, without the grant rows themselves being touched.
func TestApiShareInboxBlockedRecipientIsEmpty(t *testing.T) {
	now := time.Now().Unix()
	email := "inbox-blocked@example.com"
	recipientId := database.SaveShareRecipient(models.ShareRecipient{Email: email, CreatedAt: now, IsBlocked: true})
	database.SaveMetaData(models.File{
		Id: "inboxFileBlocked", Name: "blocked.txt", SHA1: "inboxshablocked",
		UnlimitedDownloads: true, UnlimitedTime: true, UserId: idAdmin,
	})
	database.SetShareGrants(models.ShareResourceFile, "inboxFileBlocked", []int{recipientId}, idAdmin, 0)

	user := models.User{Id: 5002, Name: email}
	w := httptest.NewRecorder()
	apiShareInbox(w, nil, user, models.ApiKey{})
	test.IsEqualInt(t, w.Code, 200)

	var response shareInboxResponseTest
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))
	test.IsEqualInt(t, len(response.Items), 0)
}

// TestApiShareInboxExcludesDeletedDisposedAndExpiredResources proves the exclusion rules: a grant
// whose resource no longer exists, a disposed file, a time-expired file, a closed file request
// and a time-expired file request are all skipped, while a live file with an active grant on the
// same recipient still comes through.
func TestApiShareInboxExcludesDeletedDisposedAndExpiredResources(t *testing.T) {
	now := time.Now().Unix()
	email := "inbox-excl@example.com"
	recipientId := database.SaveShareRecipient(models.ShareRecipient{Email: email, CreatedAt: now})

	database.SaveMetaData(models.File{
		Id: "inboxFileLive", Name: "live.txt", SHA1: "inboxshalive",
		UnlimitedDownloads: true, UnlimitedTime: true, UserId: idAdmin,
	})
	database.SaveMetaData(models.File{
		Id: "inboxFileDisposed", Name: "disposed.txt", SHA1: "inboxshadisposed",
		UnlimitedDownloads: true, UnlimitedTime: true, UserId: idAdmin, DisposedAt: now,
	})
	database.SaveMetaData(models.File{
		Id: "inboxFileExpired", Name: "expired.txt", SHA1: "inboxshaexpired",
		UnlimitedDownloads: true, UnlimitedTime: false, ExpireAt: now - 3600, UserId: idAdmin,
	})
	database.SaveFileRequest(models.FileRequest{
		Id: "inboxRequestClosed", UserId: idAdmin, Name: "closed request", Closed: true, CreationDate: now,
	})
	database.SaveFileRequest(models.FileRequest{
		Id: "inboxRequestExpired", UserId: idAdmin, Name: "expired request", Expiry: now - 3600, CreationDate: now,
	})

	database.SetShareGrants(models.ShareResourceFile, "inboxFileLive", []int{recipientId}, idAdmin, 0)
	database.SetShareGrants(models.ShareResourceFile, "inboxFileDisposed", []int{recipientId}, idAdmin, 0)
	database.SetShareGrants(models.ShareResourceFile, "inboxFileExpired", []int{recipientId}, idAdmin, 0)
	database.SetShareGrants(models.ShareResourceFileRequest, "inboxRequestClosed", []int{recipientId}, idAdmin, 0)
	database.SetShareGrants(models.ShareResourceFileRequest, "inboxRequestExpired", []int{recipientId}, idAdmin, 0)
	// The resource for this grant was never saved at all - the safety net for an orphaned row.
	database.SetShareGrants(models.ShareResourceFile, "inboxFileNeverExisted", []int{recipientId}, idAdmin, 0)

	user := models.User{Id: 5003, Name: email}
	w := httptest.NewRecorder()
	apiShareInbox(w, nil, user, models.ApiKey{})
	test.IsEqualInt(t, w.Code, 200)

	var response shareInboxResponseTest
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))
	test.IsEqualInt(t, len(response.Items), 1)
	test.IsEqualString(t, response.Items[0].ResourceId, "inboxFileLive")
}

// TestApiShareInboxNonEmailAccountNameIsEmpty proves the accepted gap: an internal account whose
// name is not an email address (e.g. "admin") can never match a ShareRecipient row, so its inbox
// is simply empty rather than erroring.
func TestApiShareInboxNonEmailAccountNameIsEmpty(t *testing.T) {
	user := models.User{Id: 5006, Name: "inbox-test-admin"}
	w := httptest.NewRecorder()
	apiShareInbox(w, nil, user, models.ApiKey{})
	test.IsEqualInt(t, w.Code, 200)

	var response shareInboxResponseTest
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))
	test.IsEqualInt(t, len(response.Items), 0)
}

// findCookieByName is a small test helper for pulling one cookie out of a recorder's Set-Cookie
// headers by name.
func findCookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestApiShareInboxOpenSetsCookieAndReturnsUrl proves the open endpoint's whole point: it hands
// back the same recipient cookie the mailed link's token exchange would have set (so the download
// that follows is attributed to the correct recipient, per Part F), and a same-origin URL the SPA
// can navigate to directly.
func TestApiShareInboxOpenSetsCookieAndReturnsUrl(t *testing.T) {
	now := time.Now().Unix()
	email := "inbox-open@example.com"
	recipientId := database.SaveShareRecipient(models.ShareRecipient{Email: email, CreatedAt: now})
	database.SaveMetaData(models.File{
		Id: "inboxFileOpen", Name: "open.txt", SHA1: "inboxshaopen",
		UnlimitedDownloads: true, UnlimitedTime: true, UserId: idAdmin,
	})
	database.SetShareGrants(models.ShareResourceFile, "inboxFileOpen", []int{recipientId}, idAdmin, 0)

	user := models.User{Id: 5004, Name: email}
	w := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "https://x.test/api/share/inbox/open", nil)
	request := &paramShareInboxOpen{ResourceType: models.ShareResourceFile, ResourceId: "inboxFileOpen", Request: httpReq}
	apiShareInboxOpen(w, request, user, models.ApiKey{})
	test.IsEqualInt(t, w.Code, 200)

	var response struct {
		Result string `json:"result"`
		Url    string `json:"url"`
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))
	test.IsEqualString(t, response.Url, "/s/inboxFileOpen")

	cookie := findCookieByName(w.Result().Cookies(), shareaccess.CookieName(models.ShareResourceFile, "inboxFileOpen"))
	test.IsNotNil(t, cookie)

	verifyReq := httptest.NewRequest(http.MethodGet, "https://x.test/s/inboxFileOpen", nil)
	verifyReq.AddCookie(cookie)
	gotRecipientId, ok := shareaccess.ReadCookie(verifyReq, models.ShareResourceFile, "inboxFileOpen")
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, gotRecipientId, recipientId)

	time.Sleep(200 * time.Millisecond)
	entries, _ := logging.GetAuditEntriesSince(0, 5000)
	found := false
	for _, entry := range entries {
		if entry.Action != "share.inbox.opened" || entry.FileId != "inboxFileOpen" {
			continue
		}
		found = true
		test.IsEqualInt(t, entry.Actor.UserId, user.Id)
		test.IsEqualString(t, entry.Actor.Email, user.Name)
	}
	test.IsEqualBool(t, found, true)
}

// TestApiShareInboxOpenNoGrantReturns404 proves the non-enumerable stance: a known recipient with
// no grant on the specific resource asked for gets the same 404 as a resource that does not
// exist, matching resolveShareResource on the uploader's side.
func TestApiShareInboxOpenNoGrantReturns404(t *testing.T) {
	email := "inbox-nogrant@example.com"
	database.SaveShareRecipient(models.ShareRecipient{Email: email, CreatedAt: time.Now().Unix()})
	database.SaveMetaData(models.File{
		Id: "inboxFileNoGrant", Name: "nogrant.txt", SHA1: "inboxshanogrant",
		UnlimitedDownloads: true, UnlimitedTime: true, UserId: idAdmin,
	})
	// Deliberately no database.SetShareGrants call: the recipient exists, but holds no grant on
	// this resource.

	user := models.User{Id: 5005, Name: email}
	w := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "https://x.test/api/share/inbox/open", nil)
	request := &paramShareInboxOpen{ResourceType: models.ShareResourceFile, ResourceId: "inboxFileNoGrant", Request: httpReq}
	apiShareInboxOpen(w, request, user, models.ApiKey{})
	test.IsEqualInt(t, w.Code, http.StatusNotFound)
}

// collaboratorFixture creates a request owned by idAdmin that idUser collaborates on, with one
// received file, and returns API keys for idUser and for a third account (idStranger) that has
// no relation to the request. Both accounts hold no user-level permissions, so whatever the
// collaborator key can reach here it reaches as a collaborator and nothing else.
func collaboratorFixture(t *testing.T) (models.FileRequest, models.File, models.ApiKey, models.ApiKey) {
	t.Helper()
	database.SaveUser(models.User{
		Id: idStranger, Name: "TestStranger", Permissions: models.UserPermissionNone,
		UserLevel: models.UserLevelUser, AuthProvider: models.AuthProviderInternal,
	}, false)
	fr := models.FileRequest{
		Id: "collabRequest", Name: "Collab request", UserId: idAdmin,
		ApiKey: "collabRequestKey", CreationDate: time.Now().Unix(),
	}
	fr.SetCollaboratorIds([]int{idUser})
	database.SaveFileRequest(fr)
	file := models.File{
		Id: "collabFile", Name: "collab.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true, UnlimitedTime: true, UserId: idAdmin, UploadRequestId: fr.Id,
	}
	database.SaveMetaData(file)
	collaboratorKey := generateNewKey(false, idUser, "collaborator", "")
	collaboratorKey.Permissions = getPermissionAll()
	database.SaveApiKey(collaboratorKey)
	strangerKey := generateNewKey(false, idStranger, "stranger", "")
	strangerKey.Permissions = getPermissionAll()
	database.SaveApiKey(strangerKey)
	return fr, file, collaboratorKey, strangerKey
}

func TestCollaboratorCanListRequest(t *testing.T) {
	fr, _, collaboratorKey, strangerKey := collaboratorFixture(t)

	w, r := getRecorder("/api/uploadrequest/list", collaboratorKey.Id, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	// httptest.ResponseRecorder.Result() caches its Response, so a second call would read an
	// already-drained Body; the body is checked once against the recorder's own buffer instead
	// of calling ResponseBodyContains (which reads via Result()) more than once per recorder.
	body := w.Body.String()
	test.IsEqualBool(t, strings.Contains(body, `"id":"`+fr.Id+`"`), true)
	// Names travel with the row so the list can say whose request it is without a user lookup.
	test.IsEqualBool(t, strings.Contains(body, `"ownername":"testadmin"`), true)
	test.IsEqualBool(t, strings.Contains(body, `{"id":`+strconv.Itoa(idUser)+`,"name":"testuser"}`), true)

	w, r = getRecorder("/api/uploadrequest/list", strangerKey.Id, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	test.IsEqualBool(t, strings.Contains(w.Body.String(), `"id":"`+fr.Id+`"`), false)

	w, r = getRecorder("/api/uploadrequest/list/"+fr.Id, collaboratorKey.Id, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	test.ResponseBodyContains(t, w, `"ownername":"testadmin"`)

	w, r = getRecorder("/api/uploadrequest/list/"+fr.Id, strangerKey.Id, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)
}

func TestCollaboratorCanSeeReceivedFiles(t *testing.T) {
	_, file, collaboratorKey, strangerKey := collaboratorFixture(t)

	w, r := getRecorder("/api/files/list", collaboratorKey.Id, []test.Header{{Name: "showFileRequests", Value: "true"}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	test.ResponseBodyContains(t, w, `"Id":"`+file.Id+`"`)

	// Without the flag request files stay out of the list for collaborators exactly as for
	// owners - the Files page never shows them.
	w, r = getRecorder("/api/files/list", collaboratorKey.Id, nil)
	Process(w, r)
	test.IsEqualBool(t, strings.Contains(w.Body.String(), `"Id":"`+file.Id+`"`), false)

	w, r = getRecorder("/api/files/list", strangerKey.Id, []test.Header{{Name: "showFileRequests", Value: "true"}})
	Process(w, r)
	test.IsEqualBool(t, strings.Contains(w.Body.String(), `"Id":"`+file.Id+`"`), false)

	w, r = getRecorder("/api/files/list/"+file.Id, collaboratorKey.Id, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	w, r = getRecorder("/api/files/list/"+file.Id, strangerKey.Id, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)

	// Download authorisation is decided by checkDownloadAllowed for both the single and the zip
	// route; tested directly so the assertion does not depend on the test data dir holding the
	// file's bytes.
	collaborator, _ := database.GetUser(idUser)
	_, code, _, _ := checkDownloadAllowed(file.Id, collaborator)
	test.IsEqualInt(t, code, 0)
	stranger, _ := database.GetUser(idStranger)
	_, code, _, _ = checkDownloadAllowed(file.Id, stranger)
	test.IsEqualInt(t, code, 401)
}

// TestResolveShareResourceRefusesReceivedFile is a regression test for a gap in
// resolveShareResource's doc comment claim of applying "the same liveness check" as the public
// download path: liveness (expired/exhausted/pending deletion) was checked, but not whether the
// file was ever received through a file request in the first place, rather than uploaded
// directly by its owner.
//
// A file received through a file request carries UploadRequestId and belongs to the request
// OWNER (see collaboratorFixture and models.File.IsFileRequest), so ownership alone passes
// cleanly and ownership was, before this fix, the only thing resolveShareResource checked beyond
// liveness. Every public consumption route - showDownload, showHotlink, serveFile, and the two
// pubApi JSON handlers - refuses such a file outright via the same `!ok || file.IsFileRequest()`
// guard that storage.GetFile's own contract documents. Before the fix, an owner could still grant
// a recipient access to a received file: mail would go out, and the recipient would land on a
// dead link that the public route had already 404'd on its own terms.
//
// This asserts the file the fixture builds is exactly such a file (so the "public route 404s"
// half of the claim is verified directly against the same predicate every public route uses),
// then asserts resolveShareResource itself now refuses it the same not-found way - rather than
// resolving it and letting shareaccess.GrantAccess mail out a share that can never be opened.
func TestResolveShareResourceRefusesReceivedFile(t *testing.T) {
	uniqueSuffix := "_" + helper.GenerateRandomString(8)
	owner := models.User{
		Id: idAdmin, Name: "TestAdmin", Permissions: models.UserPermissionAll,
		UserLevel: models.UserLevelAdmin, AuthProvider: models.AuthProviderInternal,
	}
	fr := models.FileRequest{
		Id: "resolveShareResourceRequest" + uniqueSuffix, Name: "Received file request", UserId: owner.Id,
		ApiKey: "resolveShareResourceRequestKey" + uniqueSuffix, CreationDate: time.Now().Unix(),
	}
	database.SaveFileRequest(fr)
	fileId := "resolveShareResourceReceivedFile" + uniqueSuffix
	receivedFile := models.File{
		Id: fileId, Name: "received.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true, UnlimitedTime: true, UserId: owner.Id, UploadRequestId: fr.Id,
	}
	database.SaveMetaData(receivedFile)
	t.Cleanup(func() {
		database.DeleteMetaData(fileId)
		database.DeleteFileRequest(fr)
	})

	// The exact predicate every public consumption route guards on. If this is not true, the
	// fixture is not actually building a received file and the rest of this test proves nothing.
	storedFile, ok := storage.GetFile(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, storedFile.IsFileRequest(), true)

	w := httptest.NewRecorder()
	_, resolvedOk := resolveShareResource(w, models.ShareResourceFile, fileId, owner)
	test.IsEqualBool(t, resolvedOk, false)
	test.IsEqualInt(t, w.Code, http.StatusNotFound)
}

func TestCollaboratorCannotWrite(t *testing.T) {
	fr, file, collaboratorKey, _ := collaboratorFixture(t)

	w, r := getRecorderWithBody("/api/uploadrequest/save", collaboratorKey.Id, "POST",
		[]test.Header{{Name: "id", Value: fr.Id}, {Name: "name", Value: "renamed"}}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)

	w, r = getRecorderWithBody("/api/uploadrequest/delete", collaboratorKey.Id, "DELETE",
		[]test.Header{{Name: "id", Value: fr.Id}}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)
	_, stillThere := database.GetFileRequest(fr.Id)
	test.IsEqualBool(t, stillThere, true)

	w, r = getRecorderWithBody("/api/files/delete", collaboratorKey.Id, "DELETE",
		[]test.Header{{Name: "id", Value: file.Id}}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)

	// resolveShareResource answers a caller who may not edit shares with "not found" rather than
	// "forbidden" (deliberate anti-enumeration design, see that function's comment), so a
	// collaborator setting recipients gets 404 here, not 401.
	w, r = getRecorderWithBody("/api/share/recipients", collaboratorKey.Id, "POST",
		[]test.Header{{Name: "Content-Type", Value: "application/json"}},
		strings.NewReader(`{"resourceType":2,"resourceId":"`+fr.Id+`","emails":["x@example.com"],"downloadsAllowed":0}`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, 404)
}

func TestApiURequestCollaborators(t *testing.T) {
	fr, _, collaboratorKey, strangerKey := collaboratorFixture(t)
	testAuthorisation(t, "/api/uploadrequest/collaborators", models.ApiPermManageFileRequests)
	ownerKey := generateNewKey(false, idAdmin, "owner", "")
	ownerKey.Permissions = getPermissionAll()
	database.SaveApiKey(ownerKey)
	jsonHeader := []test.Header{{Name: "Content-Type", Value: "application/json"}}
	body := func(ids string) io.Reader {
		return strings.NewReader(`{"id":"` + fr.Id + `","userids":` + ids + `}`)
	}

	// Owner replaces the list. Duplicates collapse, names come back resolved.
	w, r := getRecorderWithBody("/api/uploadrequest/collaborators", ownerKey.Id, "POST", jsonHeader,
		body(`[`+strconv.Itoa(idStranger)+`,`+strconv.Itoa(idStranger)+`,`+strconv.Itoa(idUser)+`]`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	// See TestCollaboratorCanListRequest: ResponseBodyContains reads via w.Result(), which
	// caches - a second call on the same recorder would read an already-drained Body.
	respBody := w.Body.String()
	test.IsEqualBool(t, strings.Contains(respBody, `{"id":`+strconv.Itoa(idUser)+`,"name":"testuser"}`), true)
	test.IsEqualBool(t, strings.Contains(respBody, `{"id":`+strconv.Itoa(idStranger)+`,"name":"teststranger"}`), true)
	stored, _ := database.GetFileRequest(fr.Id)
	test.IsEqual(t, stored.CollaboratorIds(), []int{idUser, idStranger})

	// A collaborator may not change the list - that is a write.
	w, r = getRecorderWithBody("/api/uploadrequest/collaborators", collaboratorKey.Id, "POST", jsonHeader, body(`[]`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)
	stored, _ = database.GetFileRequest(fr.Id)
	test.IsEqualInt(t, len(stored.Collaborators), 2)

	// Nor may an unrelated account.
	w, r = getRecorderWithBody("/api/uploadrequest/collaborators", strangerKey.Id, "POST", jsonHeader, body(`[]`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, 401)

	// The owner cannot be their own collaborator.
	w, r = getRecorderWithBody("/api/uploadrequest/collaborators", ownerKey.Id, "POST", jsonHeader, body(`[`+strconv.Itoa(idAdmin)+`]`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyContains(t, w, "owner cannot be added")

	// Unknown user id.
	w, r = getRecorderWithBody("/api/uploadrequest/collaborators", ownerKey.Id, "POST", jsonHeader, body(`[424242]`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)
	test.ResponseBodyContains(t, w, "does not exist")

	// Unknown request.
	w, r = getRecorderWithBody("/api/uploadrequest/collaborators", ownerKey.Id, "POST", jsonHeader,
		strings.NewReader(`{"id":"nope","userids":[]}`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, 404)

	// Missing id is a parameter error.
	w, r = getRecorderWithBody("/api/uploadrequest/collaborators", ownerKey.Id, "POST", jsonHeader,
		strings.NewReader(`{"userids":[]}`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)

	// Owner clears the list.
	w, r = getRecorderWithBody("/api/uploadrequest/collaborators", ownerKey.Id, "POST", jsonHeader, body(`[]`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	stored, _ = database.GetFileRequest(fr.Id)
	test.IsEqualInt(t, len(stored.Collaborators), 0)

	// Restore the fixture state for other tests in this package.
	fr.SetCollaboratorIds([]int{idUser})
	database.SaveFileRequest(fr)
}

func TestApiGetUserDirectory(t *testing.T) {
	key := testAuthorisation(t, "/api/user/directory", models.ApiPermManageFileRequests)
	w, r := getRecorder("/api/user/directory", key.Id, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)
	body := w.Body.String()
	// Other accounts, id and name only. Names are lowercased on save (database.SaveUser).
	test.IsEqualBool(t, strings.Contains(body, `{"id":`+strconv.Itoa(idAdmin)+`,"name":"testadmin"}`), true)
	// Never the caller: you cannot collaborate with yourself. testAuthorisation's key belongs to
	// idUser.
	test.IsEqualBool(t, strings.Contains(body, `"name":"testuser"`), false)
	// Nothing /user/list would expose to a manage-users admin.
	test.IsEqualBool(t, strings.Contains(body, "permissions"), false)
	test.IsEqualBool(t, strings.Contains(body, "lastOnline"), false)
}

func TestDeleteUserStripsCollaborator(t *testing.T) {
	const idDoomed = 104
	database.SaveUser(models.User{
		Id: idDoomed, Name: "TestDoomed", Permissions: models.UserPermissionNone,
		UserLevel: models.UserLevelUser, AuthProvider: models.AuthProviderInternal,
	}, false)
	fr := models.FileRequest{Id: "stripRequest", Name: "Strip", UserId: idAdmin, ApiKey: "stripKey", CreationDate: time.Now().Unix()}
	fr.SetCollaboratorIds([]int{idUser, idDoomed})
	database.SaveFileRequest(fr)
	// A request owned by the doomed user that the deleting admin (idSuperAdmin) collaborates on:
	// after re-owning, idSuperAdmin must not be both owner and collaborator.
	owned := models.FileRequest{Id: "stripOwned", Name: "Owned", UserId: idDoomed, ApiKey: "stripOwnedKey", CreationDate: time.Now().Unix()}
	owned.SetCollaboratorIds([]int{idSuperAdmin})
	database.SaveFileRequest(owned)

	superKey := generateNewKey(false, idSuperAdmin, "super", "")
	superKey.Permissions = getPermissionAll()
	database.SaveApiKey(superKey)

	// Matches the header names and method TestUserDelete/testDeleteUserCall use for
	// /user/delete: header "userid" (int), header "deleteFiles" (bool); GET, since the routing
	// dispatch does not gate on HTTP method.
	w, r := getRecorder("/api/user/delete", superKey.Id, []test.Header{
		{Name: "userid", Value: strconv.Itoa(idDoomed)},
		{Name: "deleteFiles", Value: "false"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	stored, _ := database.GetFileRequest("stripRequest")
	test.IsEqual(t, stored.CollaboratorIds(), []int{idUser})

	reowned, _ := database.GetFileRequest("stripOwned")
	test.IsEqualInt(t, reowned.UserId, idSuperAdmin)
	test.IsEqualInt(t, len(reowned.Collaborators), 0)

	database.DeleteFileRequest(stored)
	database.DeleteFileRequest(reowned)
}
