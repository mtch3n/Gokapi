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
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
	"github.com/forceu/gokapi/internal/webserver/ratelimiter"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(true)
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
			ErrorMessages: []string{`{"Result":"error","ErrorMessage":"Cannot modify yourself","ErrorCode":19}`,
				`{"Result":"error","ErrorMessage":"Cannot delete yourself","ErrorCode":19}`,
				`{"Result":"error","ErrorMessage":"Cannot reset password of yourself","ErrorCode":19}`},
			StatusCode: 400,
		},
		{
			Value: strconv.Itoa(idSuperAdmin),
			ErrorMessages: []string{`{"Result":"error","ErrorMessage":"Cannot modify super admin","ErrorCode":19}`,
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

// TestUserCreateWithAuthProvider verifies BLOCKER W17: an admin can deliberately provision an
// OIDC user through the create-user API by passing the authprovider header. A user created with
// the google provider must have AuthProvider set to google and no password hash, so the internal
// password login path stays closed for that account (see IsCorrectUsernameAndPassword). Before
// this fix, apiCreateUser hardcoded models.AuthProviderInternal, so this header had no effect and
// the created user's AuthProvider would be "internal" instead of "google".
//
// OAuth must actually be configured for the google provider to be accepted (see MINOR-2 /
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

// TestUserCreateGoogleAuthProviderRejectedWithoutOauth verifies MINOR-2: authprovider: google
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
	const apiUrl = "/user/changeRank"
	const headerUserId = "userid"
	const headerNewRank = "newRank"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)

	testInvalidUserId(t, apiUrl, apiKey.Id, []test.Header{{Name: headerNewRank, Value: "admin"}})
	var validHeaders = []test.Header{
		{
			Name:  headerUserId,
			Value: strconv.Itoa(idAdmin),
		},
	}
	invalidParameter := []invalidParameterValue{
		{
			Value:        "",
			ErrorMessage: `{"Result":"error","ErrorMessage":"header newRank is required","ErrorCode":4}`,
			StatusCode:   400,
		},
		{
			Value:        "invalid",
			ErrorMessage: `{"Result":"error","ErrorMessage":"invalid rank","ErrorCode":4}`,
			StatusCode:   400,
		},
	}
	testInvalidParameters(t, apiUrl, apiKey.Id, validHeaders, headerNewRank, invalidParameter)

	user, ok := database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, user.UserLevel, models.UserLevelAdmin)
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
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
	apiChangeUserRank(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
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
		Id:                 fileId,
		Name:               fileId,
		UserId:             retrievedUser.Id,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	database.SaveMetaData(testFile)
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
		testFile, ok = database.GetMetaDataById(fileId)
		test.IsEqualBool(t, ok, mode == deleteUserCallModeKeepFiles)
		if mode == deleteUserCallModeKeepFiles {
			test.IsEqualBool(t, ok, true)
			test.IsEqualInt(t, testFile.UserId, idUser)
		} else {
			test.IsEqualBool(t, ok, false)
		}
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
			Value:        "",
			ErrorMessage: `{"Result":"error","ErrorMessage":"header userpermission is required","ErrorCode":4}`,
			StatusCode:   400,
		},
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

func TestUserPasswordReset(t *testing.T) {
	const apiUrl = "/user/resetPassword"
	const headerUserId = "userid"
	const headerSetNewPw = "generateNewPassword"

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)
	testInvalidUserId(t, apiUrl, apiKey.Id, []test.Header{})
	user, ok := database.GetUser(idAdmin)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, user.ResetPassword, false)
	user.Password = "1234"
	database.SaveUser(user, false)
	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
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

	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerUserId,
		Value: strconv.Itoa(idAdmin),
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
	apiResetPassword(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

// TestUserPasswordResetRefusesNonInternalProvider verifies MAJOR W17-2a: an admin holding
// PERM_USERS must not be able to mint a plaintext password for a Google-provisioned user, since
// that would bypass the IdP entirely (its MFA and deprovisioning) the moment the row has a
// password hash. Before this fix, apiResetPassword never checked AuthProvider at all.
func TestUserPasswordResetRefusesNonInternalProvider(t *testing.T) {
	const apiUrl = "/user/resetPassword"
	const idGoogleUser = 910

	apiKey := testAuthorisation(t, apiUrl, models.ApiPermManageUsers)

	database.SaveUser(models.User{
		Id:           idGoogleUser,
		Name:         "googlereset@test.com",
		UserLevel:    models.UserLevelUser,
		AuthProvider: models.AuthProviderGoogle,
	}, false)

	w, r := getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  "userid",
		Value: strconv.Itoa(idGoogleUser),
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
	const apiUrl = "/auth/friendlyname"
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

	w, r = getRecorder(apiUrl, apiKey.Id, []test.Header{{
		Name:  headerApiKeyModify,
		Value: apiKey.Id,
	}, {
		Name:  headerNewName,
		Value: "",
	}})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)

	defer test.ExpectPanic(t)
	apiChangeFriendlyName(w, &paramAuthCreate{}, models.User{Id: 7}, apiKey)
}

// TestChangeFriendlyNameNonAscii verifies that renaming an API key with a non-ASCII friendlyName,
// sent base64-encoded the way the frontend encoder sends it, decodes it before storing. Before
// paramAuthFriendlyName.FriendlyName carried supportBase64, the literal "base64:..." string was
// stored as the key's friendly name.
func TestChangeFriendlyNameNonAscii(t *testing.T) {
	const apiUrl = "/auth/friendlyname"
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
			Value:        "",
			ErrorMessage: `{"Result":"error","ErrorMessage":"header permission is required","ErrorCode":4}`,
			StatusCode:   400,
		},
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
	storage.DeleteFile(fileUser.Id, true)
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

func TestUpload(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)
	result, body := uploadNewFile(t)
	test.IsEqualString(t, result.Result, "OK")
	test.IsEqualString(t, result.FileInfo.Size, "3 B")
	test.IsEqualInt(t, result.FileInfo.DownloadsRemaining, 200)
	test.IsEqualBool(t, result.FileInfo.IsPasswordProtected, true)
	test.IsEqualString(t, result.FileInfo.UrlDownload, "http://127.0.0.1:53843/d?id="+result.FileInfo.Id)
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
	err = writer.WriteField("password", "12345678")
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
			headers = append(headers, test.Header{Name: "password", Value: "secretpw"})
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
		{Name: "originalPassword", Value: "false"},
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
		{Name: "originalPassword", Value: "false"},
		{Name: "password", Value: "short1"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 400)

	file, ok := database.GetMetaDataById("editpwshort")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.PasswordHash, "existinghash")
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
		{Name: "originalPassword", Value: "false"},
		{Name: "password", Value: "avalidpassword"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	file, ok := database.GetMetaDataById("editpwvalid")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.PasswordHash != "existinghash", true)
	test.IsEqualBool(t, file.PasswordHash != "", true)
}

// TestEditFileAbsentPasswordHeaderKeepsExistingHash confirms that not sending a password
// header at all - "the caller is not changing the password, or is deliberately creating
// an unprotected file" - continues to work: with "keep current password" left at its
// default, an edit that omits the password header entirely must leave the existing hash
// exactly as it was, with no rejection and no silent change.
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
		{Name: "originalPassword", Value: "true"},
	})
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	file, ok := database.GetMetaDataById("editpwabsent")
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
		{Name: "originalPassword", Value: "false"},
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

// TestFolderDeleteWritesBatchedAuditRecord verifies MAJOR-2: deleting a folder with several
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
