package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage"
	"github.com/forceu/gokapi/internal/storage/chunking"
)

type apiRoute struct {
	Url              string               // The API endpoint
	HasWildcard      bool                 // True if the endpoint contains the ID as a sub-URL
	IsFileRequestApi bool                 // True if the endpoint is used for public uploads
	AdminOnly        bool                 // True if the endpoint requires admin/superadmin permissions
	NoJsonResponse   bool                 // True if the endpoint does not always return a JSON response
	ApiPerm          models.ApiPermission // Required permission to access the endpoint
	RequestParser    requestParser        // Parser for the supplied parameters
	execution        apiFunc              // Execution function for the endpoint
}

func (r apiRoute) Continue(w http.ResponseWriter, request requestParser, user models.User, apiKey models.ApiKey) {
	r.execution(w, request, user, apiKey)
}

type apiFunc func(w http.ResponseWriter, request requestParser, user models.User, apiKey models.ApiKey)

var routes = []apiRoute{
	{
		Url:           "/info/version",
		ApiPerm:       models.ApiPermNone,
		execution:     apiVersionInfo,
		RequestParser: nil,
	},
	{
		Url:           "/info/config",
		ApiPerm:       models.ApiPermUpload,
		execution:     apiConfigInfo,
		RequestParser: nil,
	},
	{
		// Server-wide capability flags (e.g. whether share passwords are stored, see
		// internal/features). Authenticated like every other /api/* route (a valid session/API
		// key is required), but deliberately not gated on any specific permission bit - this is
		// not per-user data, so any signed-in caller may read it.
		Url:           "/features",
		ApiPerm:       models.ApiPermNone,
		execution:     apiGetFeatures,
		RequestParser: nil,
	},
	{
		Url:            "/files/download/",
		ApiPerm:        models.ApiPermDownload,
		execution:      apiDownloadSingle,
		NoJsonResponse: true,
		HasWildcard:    true,
		RequestParser:  &paramFilesDownloadSingle{},
	},
	{
		Url:            "/files/downloadzip",
		ApiPerm:        models.ApiPermDownload,
		NoJsonResponse: true,
		execution:      apiDownloadZip,
		RequestParser:  &paramFilesDownloadZip{},
	},
	{
		Url:           "/files/changeOwner",
		ApiPerm:       models.ApiPermEdit,
		AdminOnly:     true,
		execution:     apiChangeFileOwner,
		RequestParser: &paramFilesChangeOwner{},
	},
	{
		Url:           "/files/list",
		ApiPerm:       models.ApiPermView,
		execution:     apiList,
		RequestParser: &paramFilesListAll{},
	},
	{
		Url:           "/files/list/",
		ApiPerm:       models.ApiPermView,
		execution:     apiListSingle,
		HasWildcard:   true,
		RequestParser: &paramFilesListSingle{},
	},
	{
		Url:           "/chunk/add",
		ApiPerm:       models.ApiPermUpload,
		execution:     apiChunkAdd,
		RequestParser: &paramChunkAdd{},
	},
	{
		Url:           "/chunk/complete",
		ApiPerm:       models.ApiPermUpload,
		execution:     apiChunkComplete,
		RequestParser: &paramChunkComplete{},
	},
	{
		Url:           "/files/add",
		ApiPerm:       models.ApiPermUpload,
		execution:     apiUploadFile,
		RequestParser: &paramFilesAdd{},
	},
	{
		Url:           "/files/delete",
		ApiPerm:       models.ApiPermDelete,
		execution:     apiDeleteFile,
		RequestParser: &paramFilesDelete{},
	},
	{
		Url:           "/files/duplicate",
		ApiPerm:       models.ApiPermUpload,
		execution:     apiDuplicateFile,
		RequestParser: &paramFilesDuplicate{},
	},
	{
		Url:           "/files/modify",
		ApiPerm:       models.ApiPermEdit,
		execution:     apiEditFile,
		RequestParser: &paramFilesModify{},
	},
	{
		// Sharing a resource with named email addresses. Uses ApiPermEdit
		// rather than a permission of its own: granting access to a resource
		// is a change to that resource, and inventing a bit here would leave
		// every existing key unable to do it.
		Url:           "/share/recipients",
		ApiPerm:       models.ApiPermEdit,
		execution:     apiSetShareRecipients,
		RequestParser: &paramShareRecipients{},
	},
	{
		Url:           "/share/recipients/list",
		ApiPerm:       models.ApiPermView,
		execution:     apiListShareRecipients,
		RequestParser: &paramShareRecipientsList{},
	},
	{
		// No parameters: the caller gets the shares on every resource it may
		// already list, which is what a file list needs to show who each row
		// went to without a request per row.
		Url:           "/share/recipients/summary",
		ApiPerm:       models.ApiPermView,
		execution:     apiShareRecipientsSummary,
		RequestParser: nil,
	},
	{
		// No parameters: the caller's own identity (user.Name matched against a
		// ShareRecipient email) is what selects the grants to return, so there is
		// nothing for the client to supply.
		Url:           "/share/inbox",
		ApiPerm:       models.ApiPermView,
		execution:     apiShareInbox,
		RequestParser: nil,
	},
	{
		// ApiPermDownload because this issues a download-capable recipient
		// cookie for the resource, the same class of credential a mailed link
		// hands out.
		Url:           "/share/inbox/open",
		ApiPerm:       models.ApiPermDownload,
		execution:     apiShareInboxOpen,
		RequestParser: &paramShareInboxOpen{},
	},
	{
		Url:           "/files/replace",
		ApiPerm:       models.ApiPermReplace,
		execution:     apiReplaceFile,
		RequestParser: &paramFilesReplace{},
	},
	{
		Url:           "/files/restore",
		ApiPerm:       models.ApiPermDelete,
		execution:     apiRestoreFile,
		RequestParser: &paramFilesRestore{},
	},
	{
		// /files/{id}/sharekey - the ID sits in the middle of the URL rather than at a fixed
		// prefix like the other /files/* wildcard routes, so ID and suffix are both parsed in
		// paramFilesShareKey.ProcessParameter. Registered after every other /files/* route so
		// those more specific exact/prefix matches are always tried first (see getRouting) -
		// this one only ever catches genuine {id}/sharekey requests.
		Url:           "/files/",
		ApiPerm:       models.ApiPermView,
		execution:     apiGetShareKey,
		HasWildcard:   true,
		RequestParser: &paramFilesShareKey{},
	},
	{
		Url:           "/auth/info",
		ApiPerm:       models.ApiPermNone,
		execution:     apiAuthInfo,
		RequestParser: nil,
	},
	{
		Url:           "/auth/create",
		ApiPerm:       models.ApiPermApiMod,
		execution:     apiCreateApiKey,
		RequestParser: &paramAuthCreate{},
	},
	{
		Url:           "/auth/modify",
		ApiPerm:       models.ApiPermApiMod,
		execution:     apiModifyApiKey,
		RequestParser: &paramAuthModify{},
	},
	{
		Url:           "/auth/delete",
		ApiPerm:       models.ApiPermApiMod,
		execution:     apiDeleteKey,
		RequestParser: &paramAuthDelete{},
	},
	{
		Url:           "/auth/list",
		ApiPerm:       models.ApiPermApiMod,
		execution:     apiGetAuthList,
		RequestParser: nil,
	},
	{
		Url:           "/user/me",
		ApiPerm:       models.ApiPermNone,
		execution:     apiGetCurrentUser,
		RequestParser: nil,
	},
	{
		Url:           "/user/avatar",
		ApiPerm:       models.ApiPermNone,
		execution:     apiGetUserAvatar,
		RequestParser: nil,
	},
	{
		Url:           "/user/list",
		ApiPerm:       models.ApiPermManageUsers,
		execution:     apiGetUserList,
		RequestParser: nil,
	},
	{
		// Id and name of every other account, so a user who may manage file requests can pick
		// collaborators without holding ManageUsers, which /user/list needs and which would also
		// expose permissions and last-login.
		Url:           "/user/directory",
		ApiPerm:       models.ApiPermManageFileRequests,
		execution:     apiGetUserDirectory,
		RequestParser: nil,
	},
	{
		Url:           "/user/create",
		ApiPerm:       models.ApiPermManageUsers,
		execution:     apiCreateUser,
		RequestParser: &paramUserCreate{},
	},
	{
		Url:           "/user/delete",
		ApiPerm:       models.ApiPermManageUsers,
		execution:     apiDeleteUser,
		RequestParser: &paramUserDelete{},
	},
	{
		Url:           "/user/modify",
		ApiPerm:       models.ApiPermManageUsers,
		execution:     apiModifyUser,
		RequestParser: &paramUserModify{},
	},
	{
		Url:           "/uploadrequest/list",
		ApiPerm:       models.ApiPermManageFileRequests,
		execution:     apiUploadRequestList,
		RequestParser: nil,
	},
	{
		Url:           "/uploadrequest/list/",
		ApiPerm:       models.ApiPermManageFileRequests,
		execution:     apiUploadRequestListSingle,
		HasWildcard:   true,
		RequestParser: &paramURequestListSingle{},
	},
	{
		Url:           "/uploadrequest/save",
		ApiPerm:       models.ApiPermManageFileRequests,
		execution:     apiURequestSave,
		RequestParser: &paramURequestSave{},
	},
	{
		Url:           "/uploadrequest/delete",
		ApiPerm:       models.ApiPermManageFileRequests,
		execution:     apiURequestDelete,
		RequestParser: &paramURequestDelete{},
	},
	{
		// Replaces the collaborator list of a request (models.FileRequest.Collaborators). A JSON
		// body rather than headers because the list is variable length, same as /share/recipients.
		Url:           "/uploadrequest/collaborators",
		ApiPerm:       models.ApiPermManageFileRequests,
		execution:     apiURequestCollaborators,
		RequestParser: &paramURequestCollaborators{},
	},
	{
		Url:           "/folder/create",
		ApiPerm:       models.ApiPermUpload,
		execution:     apiFolderCreate,
		RequestParser: &paramFolderCreate{},
	},
	{
		Url:           "/folder/list",
		ApiPerm:       models.ApiPermView,
		execution:     apiFolderList,
		RequestParser: nil,
	},
	{
		Url:           "/folder/delete",
		ApiPerm:       models.ApiPermDelete,
		execution:     apiFolderDelete,
		RequestParser: &paramFolderDelete{},
	},
	{
		Url:           "/folder/modify",
		ApiPerm:       models.ApiPermEdit,
		execution:     apiFolderModify,
		RequestParser: &paramFolderModify{},
	},
	{
		// /folder/{id}/sharekey - the ID sits in the middle of the URL, same as
		// /files/{id}/sharekey (see paramFilesShareKey). Registered after every other exact
		// /folder/* route so those are always tried first (see getRouting) - this one only ever
		// catches genuine {id}/sharekey requests.
		Url:           "/folder/",
		ApiPerm:       models.ApiPermView,
		execution:     apiGetFolderShareKey,
		HasWildcard:   true,
		RequestParser: &paramFolderShareKey{},
	},
	{
		Url:              "/uploadrequest/chunk/add",
		ApiPerm:          models.ApiPermNone,
		execution:        apiChunkUploadRequestAdd,
		IsFileRequestApi: true,
		RequestParser:    &paramChunkUploadRequestAdd{},
	},
	{
		Url:              "/uploadrequest/chunk/complete",
		ApiPerm:          models.ApiPermNone,
		IsFileRequestApi: true,
		execution:        apiChunkUploadRequestComplete,
		RequestParser:    &paramChunkUploadRequestComplete{},
	},
	{
		Url:              "/uploadrequest/chunk/reserve",
		ApiPerm:          models.ApiPermNone,
		IsFileRequestApi: true,
		execution:        apiChunkReserve,
		RequestParser:    &paramChunkReserve{},
	},
	{
		Url:              "/uploadrequest/chunk/unreserve",
		ApiPerm:          models.ApiPermNone,
		IsFileRequestApi: true,
		execution:        apiChunkUnreserve,
		RequestParser:    &paramChunkUnreserve{},
	},
	{
		Url:              "/uploadrequest/complete",
		ApiPerm:          models.ApiPermNone,
		IsFileRequestApi: true,
		execution:        apiURequestComplete,
		RequestParser:    &paramURequestComplete{},
	},
	{
		Url:           "/logs/delete",
		ApiPerm:       models.ApiPermManageLogs,
		AdminOnly:     true,
		execution:     apiLogsDelete,
		RequestParser: &paramLogsDelete{},
	},
	{
		Url:           "/logs/systemStatus",
		ApiPerm:       models.ApiPermManageLogs,
		execution:     apiLogSystemStatus,
		RequestParser: nil,
	},
	{
		Url:           "/logs/resetTraffic",
		ApiPerm:       models.ApiPermManageLogs,
		AdminOnly:     true,
		execution:     apiLogResetTraffic,
		RequestParser: nil,
	},
	{
		Url:           "/logs/get",
		ApiPerm:       models.ApiPermManageLogs,
		execution:     apiLogsGet,
		RequestParser: &paramLogsGet{},
	},
	{
		Url:           "/logs/audit",
		ApiPerm:       models.ApiPermManageLogs,
		execution:     apiLogsAudit,
		RequestParser: &paramLogsAudit{},
	},
	{
		Url:           "/e2e/get", // not published in API documentation
		ApiPerm:       models.ApiPermUpload,
		execution:     apiE2eGet,
		RequestParser: nil,
	},
	{
		Url:           "/e2e/set", // not published in API documentation
		ApiPerm:       models.ApiPermUpload,
		execution:     apiE2eSet,
		RequestParser: &paramE2eStore{},
	},
	{
		Url:           "/e2e/mutex/lock", // not published in API documentation
		ApiPerm:       models.ApiPermUpload,
		execution:     apiE2eMutexLock,
		RequestParser: nil,
	},
	{
		Url:           "/e2e/mutex/unlock", // not published in API documentation
		ApiPerm:       models.ApiPermUpload,
		execution:     apiE2eMutexUnlock,
		RequestParser: nil,
	},
}

func getRouting(requestUrl string) (apiRoute, bool) {
	for _, route := range routes {
		if (!route.HasWildcard && requestUrl == route.Url) ||
			(route.HasWildcard && strings.HasPrefix(requestUrl, route.Url)) {
			return route, true
		}
	}
	return apiRoute{}, false
}

type requestParser interface {
	// ParseRequest reads the supplied headers, stores them and afterwards calls ProcessParameter()
	ParseRequest(r *http.Request) error
	// ProcessParameter goes through the submitted parameters, checks them and converts them to expected values
	ProcessParameter(r *http.Request) error
	// New returns an empty struct of the type
	New() requestParser
}

type paramFilesListAll struct {
	ShowFileRequests bool `header:"showFileRequests"`
	foundHeaders     map[string]bool
}

func (p *paramFilesListAll) ProcessParameter(_ *http.Request) error {
	return nil
}

// paramFilesShareKey carries the ID parsed out of GET /files/{id}/sharekey. No header fields,
// so the code generator emits a ParseRequest that only calls ProcessParameter (see
// paramFilesListSingle above).
type paramFilesShareKey struct {
	Id string
}

func (p *paramFilesShareKey) ProcessParameter(r *http.Request) error {
	url := parseRequestUrl(r)
	trimmed := strings.TrimPrefix(url, "/files/")
	if !strings.HasSuffix(trimmed, "/sharekey") {
		return errors.New("invalid request")
	}
	id := strings.TrimSuffix(trimmed, "/sharekey")
	if id == "" {
		return errors.New("invalid request")
	}
	p.Id = id
	return nil
}

type paramFilesListSingle struct {
	Id string
}

func (p *paramFilesListSingle) ProcessParameter(r *http.Request) error {
	url := parseRequestUrl(r)
	p.Id = strings.TrimPrefix(url, "/files/list/")
	return nil
}

type paramFilesDownloadSingle struct {
	Id              string
	WebRequest      *http.Request
	IncreaseCounter bool `header:"increaseCounter"`
	PresignUrl      bool `header:"presignUrl"`
	foundHeaders    map[string]bool
}

func (p *paramFilesDownloadSingle) ProcessParameter(r *http.Request) error {
	p.WebRequest = r
	url := parseRequestUrl(r)
	p.Id = strings.TrimPrefix(url, "/files/download/")
	return nil
}

type paramFilesDownloadZip struct {
	Ids             []string
	WebRequest      *http.Request
	FileIds         string `header:"ids" required:"true"`
	Filename        string `header:"filename" supportBase64:"true"`
	IncreaseCounter bool   `header:"increaseCounter"`
	PresignUrl      bool   `header:"presignUrl"`
	foundHeaders    map[string]bool
}

func (p *paramFilesDownloadZip) ProcessParameter(r *http.Request) error {
	ids := strings.Split(p.FileIds, ",")
	slices.Sort(ids)
	p.Ids = slices.Compact(ids)
	p.WebRequest = r
	return nil
}

type paramFilesAdd struct {
	Request *http.Request
}

func (p *paramFilesAdd) ProcessParameter(r *http.Request) error {
	p.Request = r
	return nil
}

type paramFilesChangeOwner struct {
	Id           string `header:"id" required:"true"`
	NewOwner     int    `header:"newOwner" required:"true"`
	foundHeaders map[string]bool
}

func (p *paramFilesChangeOwner) ProcessParameter(_ *http.Request) error {
	return nil
}

type paramFilesDuplicate struct {
	Id                 string `header:"id" required:"true"`
	AllowedDownloads   int    `header:"allowedDownloads"`
	ExpiryDays         int    `header:"expiryDays"`
	Password           string `header:"password" supportBase64:"true"`
	KeepPassword       bool   `header:"originalPassword"`
	FileName           string `header:"filename"`
	UnlimitedDownloads bool
	UnlimitedTime      bool
	RequestedChanges   int
	foundHeaders       map[string]bool
}

func (p *paramFilesDuplicate) ProcessParameter(r *http.Request) error {
	if p.foundHeaders["allowedDownloads"] {
		p.RequestedChanges |= storage.ParamDownloads
		if p.AllowedDownloads == 0 {
			p.UnlimitedDownloads = true
		}
	}
	if p.foundHeaders["expiryDays"] {
		p.RequestedChanges |= storage.ParamExpiry
		if p.ExpiryDays == 0 {
			p.UnlimitedTime = true
		}
	}
	if !p.KeepPassword {
		if p.foundHeaders["password"] {
			p.RequestedChanges |= storage.ParamPassword
		}
	}
	if p.foundHeaders["filename"] {
		p.RequestedChanges |= storage.ParamName
		p.FileName = helper.SanitiseFilename(p.FileName)
	}
	return nil
}

// paramFilesModify's password semantics are deliberately the same as paramFilesDuplicate's
// (see ProcessParameter below and apiDuplicateFile in Api.go): whether the password header
// was actually PRESENT on the request - not whether a "keep the original" flag defaulted to
// false - is the only signal that decides whether the password is touched at all. Omitting
// both headers must be indistinguishable from an explicit "keep current password", never an
// implicit "remove it". Removal is its own explicit signal (RemovePassword), so a caller can
// never wipe a password as the side effect of leaving an optional header off a request.
type paramFilesModify struct {
	Id               string `header:"id" required:"true"`
	AllowedDownloads int    `header:"allowedDownloads"`
	ExpiryTimestamp  int64  `header:"expiryTimestamp"`
	Password         string `header:"password" supportBase64:"true"`
	// GeneratedPassword signals that Password was generated by the SPA rather than typed by
	// the user, exactly as on paramChunkComplete. Informational only: the new password is kept
	// in encrypted form for GET /files/{id}/sharekey whether it was typed or generated, so this
	// currently decides nothing - see storage.EncryptSharePassword.
	GeneratedPassword  bool `header:"generatedpassword"`
	RemovePassword     bool `header:"removePassword"`
	UnlimitedDownloads bool
	UnlimitedExpiry    bool
	IsPasswordSet      bool
	foundHeaders       map[string]bool
}

func (p *paramFilesModify) ProcessParameter(_ *http.Request) error {
	if p.foundHeaders["allowedDownloads"] && p.AllowedDownloads == 0 {
		p.UnlimitedDownloads = true
	}
	if p.foundHeaders["expiryTimestamp"] && p.ExpiryTimestamp == 0 {
		p.UnlimitedExpiry = true
	}
	p.IsPasswordSet = p.foundHeaders["password"]
	if p.IsPasswordSet && p.RemovePassword {
		return errors.New("cannot set both password and removePassword")
	}
	return nil
}

type paramFilesReplace struct {
	Id            string `header:"id" required:"true"`
	IdNewContent  string `header:"idNewContent" required:"true"`
	DeleteNewFile bool   `header:"deleteNewFile"`
	foundHeaders  map[string]bool
}

func (p *paramFilesReplace) ProcessParameter(_ *http.Request) error { return nil }

type paramFilesDelete struct {
	Id           string `header:"id" required:"true"`
	DelaySeconds int    `header:"delay"`
	foundHeaders map[string]bool
}

func (p *paramFilesDelete) ProcessParameter(_ *http.Request) error { return nil }

type paramFilesRestore struct {
	Id           string `header:"id" required:"true"`
	foundHeaders map[string]bool
}

func (p *paramFilesRestore) ProcessParameter(_ *http.Request) error { return nil }

type paramAuthCreate struct {
	FriendlyName     string `header:"friendlyName" supportBase64:"true"`
	BasicPermissions bool   `header:"basicPermissions"`
	foundHeaders     map[string]bool
}

func (p *paramAuthCreate) ProcessParameter(_ *http.Request) error { return nil }

// paramAuthModify carries the merged /auth/modify payload: a permission grant/revoke and a
// friendly-name rename used to each be their own endpoint (/auth/modify and
// /auth/friendlyname), each rolling its own copy of the same ownership/permission guard - see
// apiModifyApiKey. Either mutation, or both together, may be requested in one call; at least one
// is required.
type paramAuthModify struct {
	KeyId                 string `header:"targetKey" required:"true"`
	permissionRaw         string `header:"permission"`
	permissionModifierRaw string `header:"permissionModifier"`
	Permission            models.ApiPermission
	GrantPermission       bool
	IsPermissionSet       bool
	FriendlyName          string `header:"friendlyName" supportBase64:"true"`
	IsFriendlyNameSet     bool
	foundHeaders          map[string]bool
}

func (p *paramAuthModify) ProcessParameter(_ *http.Request) error {
	if p.foundHeaders["permission"] || p.foundHeaders["permissionModifier"] {
		if !p.foundHeaders["permission"] || !p.foundHeaders["permissionModifier"] {
			return errors.New("permission and permissionModifier must be provided together")
		}
		permission, err := models.ApiPermissionFromString(p.permissionRaw)
		if err != nil {
			return err
		}
		p.Permission = permission
		switch strings.ToUpper(p.permissionModifierRaw) {
		case "GRANT":
			p.GrantPermission = true
		case "REVOKE":
			p.GrantPermission = false
		default:
			return errors.New("invalid permission modifier")
		}
		p.IsPermissionSet = true
	}
	if p.foundHeaders["friendlyName"] {
		p.IsFriendlyNameSet = true
	}
	if !p.IsPermissionSet && !p.IsFriendlyNameSet {
		return errors.New("no mutation requested")
	}
	return nil
}

type paramAuthDelete struct {
	KeyId        string `header:"targetKey" required:"true"`
	foundHeaders map[string]bool
}

func (p *paramAuthDelete) ProcessParameter(_ *http.Request) error { return nil }

type paramUserCreate struct {
	Username        string `header:"username" required:"true" supportBase64:"true"`
	authProviderRaw string `header:"authprovider"`
	AuthProvider    string
	foundHeaders    map[string]bool
}

// ProcessParameter defaults an absent authprovider header to models.AuthProviderInternal and
// rejects any value that is not one of the two known provider constants. This is the only way an
// admin can deliberately provision an OIDC user through the API: user/create must not silently
// accept an arbitrary string here, since AuthProvider gates both the password and OIDC login
// paths (see authentication.IsCorrectUsernameAndPassword and authentication.getOrCreateUser).
//
// The google provider is additionally rejected unless OAuth is actually configured (hybrid mode
// enabled, or Method is OAuth2). Without this, an admin (or a script run before OAuth is set up,
// or left over after OAuth is disabled again) could create a row that can log in through neither
// door - and that row becomes a live, silently self-registering SSO account the moment an admin
// enables hybrid mode later, since it already carries AuthProvider "google" and there is no
// review step in between.
func (p *paramUserCreate) ProcessParameter(_ *http.Request) error {
	if p.authProviderRaw == "" {
		p.AuthProvider = models.AuthProviderInternal
		return nil
	}
	switch p.authProviderRaw {
	case models.AuthProviderInternal:
		p.AuthProvider = p.authProviderRaw
		return nil
	case models.AuthProviderGoogle:
		authConfig := configuration.Get().Authentication
		isOauthConfigured := authConfig.Method == models.AuthenticationOAuth2 ||
			(authConfig.Method == models.AuthenticationInternal && authConfig.OAuthEnabledAlongsideInternal)
		if !isOauthConfigured {
			return errors.New("authprovider google requires OAuth to be configured")
		}
		p.AuthProvider = p.authProviderRaw
		return nil
	default:
		return errors.New("invalid value for header authprovider")
	}
}

type paramUserDelete struct {
	Id           int  `header:"userid" required:"true"`
	DeleteFiles  bool `header:"deleteFiles"`
	foundHeaders map[string]bool
}

func (p *paramUserDelete) ProcessParameter(_ *http.Request) error { return nil }

// paramUserModify carries the merged /user/modify payload: a rank change, a permission
// grant/revoke and a password reset used to each be their own endpoint (/user/changeRank,
// /user/modify and /user/resetPassword), each rolling its own copy of the same
// never-super-admin/never-yourself/must-outrank guard - see apiModifyUser and
// canAdministerUser. Any one of the three mutations, or any combination of them, may be
// requested in one call; at least one is required.
type paramUserModify struct {
	Id                    int    `header:"userid" required:"true"`
	newRankRaw            string `header:"newRank"`
	NewRank               models.UserRank
	IsRankSet             bool
	Permission            models.UserPermission
	permissionRaw         string `header:"userpermission"`
	permissionModifierRaw string `header:"permissionModifier"`
	GrantPermission       bool
	IsPermissionSet       bool
	ResetPassword         bool `header:"resetPassword"`
	GenerateNewPassword   bool `header:"generateNewPassword"`
	foundHeaders          map[string]bool
}

func (p *paramUserModify) ProcessParameter(_ *http.Request) error {
	if p.foundHeaders["newRank"] {
		switch strings.ToLower(p.newRankRaw) {
		case "admin":
			p.NewRank = models.UserLevelAdmin
		case "user":
			p.NewRank = models.UserLevelUser
		default:
			return errors.New("invalid rank")
		}
		p.IsRankSet = true
	}
	if p.foundHeaders["userpermission"] || p.foundHeaders["permissionModifier"] {
		if !p.foundHeaders["userpermission"] || !p.foundHeaders["permissionModifier"] {
			return errors.New("userpermission and permissionModifier must be provided together")
		}
		switch strings.ToUpper(p.permissionRaw) {
		case "PERM_REPLACE":
			p.Permission = models.UserPermReplaceUploads
		case "PERM_LIST":
			p.Permission = models.UserPermListOtherUploads
		case "PERM_EDIT":
			p.Permission = models.UserPermEditOtherUploads
		case "PERM_REPLACE_OTHER":
			p.Permission = models.UserPermReplaceOtherUploads
		case "PERM_DELETE":
			p.Permission = models.UserPermDeleteOtherUploads
		case "PERM_LOGS":
			p.Permission = models.UserPermManageLogs
		case "PERM_API":
			p.Permission = models.UserPermManageApiKeys
		case "PERM_USERS":
			p.Permission = models.UserPermManageUsers
		case "PERM_GUEST_UPLOAD":
			p.Permission = models.UserPermGuestUploads
		default:
			return errors.New("invalid permission")
		}
		switch strings.ToUpper(p.permissionModifierRaw) {
		case "GRANT":
			p.GrantPermission = true
		case "REVOKE":
			p.GrantPermission = false
		default:
			return errors.New("invalid permission modifier")
		}
		p.IsPermissionSet = true
	}
	if !p.IsRankSet && !p.IsPermissionSet && !p.ResetPassword {
		return errors.New("no mutation requested")
	}
	return nil
}

type paramE2eStore struct {
	EncryptedInfo models.E2EInfoEncrypted
	foundHeaders  map[string]bool
}

func (p *paramE2eStore) ProcessParameter(r *http.Request) error {
	const maxBodySize = 5 * 1024 * 1024 // 5MB in bytes
	bodyReader := http.MaxBytesReader(nil, r.Body, maxBodySize)

	type expectedInput struct {
		Content string `json:"content"`
	}
	var input expectedInput

	err := json.NewDecoder(bodyReader).Decode(&input)
	if err != nil {
		// If body is larger than 5MB, this will be returned here as an error
		return err
	}

	content, err := base64.StdEncoding.DecodeString(input.Content)
	if err != nil {
		return err
	}
	return json.Unmarshal(content, &p.EncryptedInfo)
}

// paramShareRecipients carries an email list for one resource. A JSON body
// rather than headers, because the list is variable length and an address can
// contain characters that do not survive a header cleanly.
type paramShareRecipients struct {
	ResourceType     int      `json:"resourceType"`
	ResourceId       string   `json:"resourceId"`
	Emails           []string `json:"emails"`
	DownloadsAllowed int      `json:"downloadsAllowed"`
	foundHeaders     map[string]bool
}

func (p *paramShareRecipients) ProcessParameter(r *http.Request) error {
	// Bounded so a malformed or hostile request cannot force the server to
	// buffer an unbounded body before it is even authorised to act.
	const maxBodySize = 64 * 1024
	bodyReader := http.MaxBytesReader(nil, r.Body, maxBodySize)
	if err := json.NewDecoder(bodyReader).Decode(p); err != nil {
		return err
	}
	if p.ResourceId == "" {
		return errors.New("resourceId is required")
	}
	if !models.IsValidShareResourceType(p.ResourceType) {
		return errors.New("unknown resourceType")
	}
	if p.DownloadsAllowed < 0 {
		return errors.New("downloadsAllowed cannot be negative")
	}
	return nil
}

type paramShareRecipientsList struct {
	ResourceType int    `header:"resourceType"`
	ResourceId   string `header:"resourceId" required:"true"`
	foundHeaders map[string]bool
}

func (p *paramShareRecipientsList) ProcessParameter(_ *http.Request) error {
	if !models.IsValidShareResourceType(p.ResourceType) {
		return errors.New("unknown resourceType")
	}
	return nil
}

type paramShareInboxOpen struct {
	ResourceType int    `header:"resourceType"`
	ResourceId   string `header:"resourceId" required:"true"`
	Request      *http.Request
	foundHeaders map[string]bool
}

func (p *paramShareInboxOpen) ProcessParameter(r *http.Request) error {
	if !models.IsValidShareResourceType(p.ResourceType) {
		return errors.New("unknown resourceType")
	}
	p.Request = r
	return nil
}

type paramLogsDelete struct {
	Timestamp    int64 `header:"timestamp"`
	Request      *http.Request
	foundHeaders map[string]bool
}

func (p *paramLogsDelete) ProcessParameter(r *http.Request) error {
	p.Request = r
	return nil
}

type paramLogsGet struct {
	Timestamp    int64 `header:"timestamp"`
	foundHeaders map[string]bool
}

func (p *paramLogsGet) ProcessParameter(_ *http.Request) error {
	return nil
}

type paramLogsAudit struct {
	FromSeq      int64 `header:"fromSeq"`
	Limit        int   `header:"limit"`
	foundHeaders map[string]bool
}

func (p *paramLogsAudit) ProcessParameter(_ *http.Request) error {
	return nil
}

type paramChunkAdd struct {
	Request *http.Request
}

func (p *paramChunkAdd) ProcessParameter(r *http.Request) error {
	p.Request = r
	return nil
}

func (p *paramChunkAdd) GetRequest() *http.Request {
	return p.Request
}

type paramChunkUploadRequestAdd struct {
	Request       *http.Request
	FileRequestId string `header:"fileRequestId" required:"true"`
	foundHeaders  map[string]bool
}

func (p *paramChunkUploadRequestAdd) ProcessParameter(r *http.Request) error {
	p.Request = r
	return nil
}
func (p *paramChunkUploadRequestAdd) GetRequest() *http.Request {
	return p.Request
}

type paramChunkComplete struct {
	Uuid             string `header:"uuid" required:"true"`
	FileName         string `header:"filename" required:"true" supportBase64:"true"`
	FileSize         int64  `header:"filesize" required:"true"`
	RealSize         int64  `header:"realsize" unpublished:"true"` // not published in API documentation
	ContentType      string `header:"contenttype"`
	AllowedDownloads int    `header:"allowedDownloads"`
	ExpiryDays       int    `header:"expiryDays"`
	// ExpiryTimestamp, if set, is an absolute Unix timestamp and takes precedence over
	// ExpiryDays - see fileupload.CreateUploadConfig. Named the same as paramFilesModify's
	// header of the same purpose.
	ExpiryTimestamp int64  `header:"expiryTimestamp"`
	Password        string `header:"password" supportBase64:"true"`
	// GeneratedPassword signals that Password was generated client-side by the SPA rather than
	// typed by the uploader (its accessMode is "generated", not "manual"). Only meaningful
	// together with a non-empty password. Informational only: it gates nothing today, because
	// storage.EncryptSharePassword stores a typed password on the same terms as a generated
	// one. It is the signal that would be re-gated on to restore the old rule.
	GeneratedPassword bool   `header:"generatedpassword"`
	BundleId          string `header:"bundleid"`
	IsE2E             bool   `header:"isE2E" unpublished:"true"` // not published in API documentation
	IsNonBlocking     bool   `header:"nonblocking"`
	// Recipients is a comma-separated list of email addresses, the same list-in-a-header
	// convention paramFilesDownloadZip uses for "ids". When non-empty, the file (or its
	// bundle, if bundleid is also set) is restricted to these recipients as part of the
	// same request that creates it, per the 2026-09-02 audit decision that a recipient-only
	// share must never have a window where it exists with no password and no grants - see
	// grantUploadRecipients in Api.go. A JSON body was not used here the way
	// paramShareRecipients uses one, because this endpoint's body is reserved for chunk
	// bytes on the earlier /chunk/add calls and carries nothing on this one.
	Recipients string `header:"recipients"`
	// RecipientEmails is Recipients split on commas and cleaned up; see ProcessParameter.
	RecipientEmails    []string
	UnlimitedDownloads bool
	UnlimitedTime      bool
	WebRequest         *http.Request
	FileHeader         chunking.FileHeader
	foundHeaders       map[string]bool
}

func (p *paramChunkComplete) ProcessParameter(r *http.Request) error {
	p.WebRequest = r

	if !p.foundHeaders["realsize"] {
		if !p.IsE2E {
			p.RealSize = p.FileSize
		} else {
			return errors.New("e2e set, but realsize not submitted")
		}
	}

	if p.AllowedDownloads == 0 {
		if p.foundHeaders["allowedDownloads"] {
			p.UnlimitedDownloads = true
		} else {
			p.AllowedDownloads = 1
		}
	}

	if p.ExpiryDays == 0 {
		if p.foundHeaders["expiryDays"] {
			p.UnlimitedTime = true
		} else {
			p.ExpiryDays = 14
		}
	} else {
		if p.ExpiryDays > 100000 {
			p.UnlimitedTime = true
		}
	}

	if p.ExpiryTimestamp != 0 && p.ExpiryTimestamp < time.Now().Unix() {
		return errors.New("expiryTimestamp is in the past")
	}

	if p.Recipients != "" {
		emails := make([]string, 0, strings.Count(p.Recipients, ",")+1)
		for _, email := range strings.Split(p.Recipients, ",") {
			email = strings.TrimSpace(email)
			if email != "" {
				emails = append(emails, email)
			}
		}
		p.RecipientEmails = emails
	}

	p.FileName = helper.SanitiseFilename(p.FileName)
	if p.FileName == "" {
		return errors.New("empty or invalid filename provided")
	}
	p.ContentType = helper.SanitiseContentType(p.ContentType)
	p.FileHeader = chunking.FileHeader{
		Filename:    p.FileName,
		ContentType: p.ContentType,
		Size:        p.FileSize,
	}
	return nil
}

type paramChunkReserve struct {
	Id           string `header:"id" required:"true"`
	WebRequest   *http.Request
	foundHeaders map[string]bool
}

func (p *paramChunkReserve) ProcessParameter(r *http.Request) error {
	p.WebRequest = r
	return nil
}

type paramChunkUnreserve struct {
	Id           string `header:"id" required:"true"`
	Uuid         string `header:"uuid" required:"true"`
	WebRequest   *http.Request
	foundHeaders map[string]bool
}

func (p *paramChunkUnreserve) ProcessParameter(r *http.Request) error {
	p.WebRequest = r
	return nil
}

type paramChunkUploadRequestComplete struct {
	Uuid          string `header:"uuid" required:"true"`
	FileName      string `header:"filename" required:"true" supportBase64:"true"`
	FileRequestId string `header:"fileRequestId" required:"true"`
	FileSize      int64  `header:"filesize" required:"true"`
	ContentType   string `header:"contenttype"`
	IsNonBlocking bool   `header:"nonblocking"`
	ApiKey        string `header:"apikey" unpublished:"true"` // not published in API documentation
	WebRequest    *http.Request
	FileHeader    chunking.FileHeader
	foundHeaders  map[string]bool
}

func (p *paramChunkUploadRequestComplete) ProcessParameter(r *http.Request) error {
	p.WebRequest = r
	p.ContentType = helper.SanitiseContentType(p.ContentType)
	p.FileName = helper.SanitiseFilename(p.FileName)
	if p.FileName == "" {
		return errors.New("empty or invalid filename provided")
	}
	p.FileHeader = chunking.FileHeader{
		Filename:    p.FileName,
		ContentType: p.ContentType,
		Size:        p.FileSize,
	}
	return nil
}

type paramURequestDelete struct {
	Id           string `header:"id" required:"true"`
	foundHeaders map[string]bool
}

func (p *paramURequestDelete) ProcessParameter(_ *http.Request) error {
	return nil
}

// paramURequestCollaborators carries the full replacement collaborator list for one request.
type paramURequestCollaborators struct {
	Id           string `json:"id"`
	UserIds      []int  `json:"userids"`
	foundHeaders map[string]bool
}

func (p *paramURequestCollaborators) ProcessParameter(r *http.Request) error {
	// Bounded so a malformed or hostile request cannot force the server to buffer an unbounded
	// body before it is even authorised to act.
	const maxBodySize = 64 * 1024
	bodyReader := http.MaxBytesReader(nil, r.Body, maxBodySize)
	if err := json.NewDecoder(bodyReader).Decode(p); err != nil {
		return err
	}
	if p.Id == "" {
		return errors.New("id is required")
	}
	return nil
}

// paramFolderCreate's optional password/expiry/downloads headers give the bundle its own
// settings at creation time - the only settings a folder now has, replacing the old "derived
// from whichever member happens to carry one" behaviour (see models.FileBundle.PasswordHash and
// friends). Same header names, and the same "absent header leaves the field untouched" and
// "present header with a zero value means unlimited" conventions as paramFilesModify, so a
// caller that already knows how to edit a file's own settings needs nothing new to learn. Leaving
// every header off keeps the bundle at filebundle.Create's own defaults (open, no limits).
type paramFolderCreate struct {
	Name               string `header:"name" required:"true" supportBase64:"true"`
	AllowedDownloads   int    `header:"allowedDownloads"`
	ExpiryTimestamp    int64  `header:"expiryTimestamp"`
	Password           string `header:"password" supportBase64:"true"`
	GeneratedPassword  bool   `header:"generatedpassword"`
	UnlimitedDownloads bool
	UnlimitedExpiry    bool
	IsPasswordSet      bool
	foundHeaders       map[string]bool
}

func (p *paramFolderCreate) ProcessParameter(_ *http.Request) error {
	if p.foundHeaders["allowedDownloads"] && p.AllowedDownloads == 0 {
		p.UnlimitedDownloads = true
	}
	if p.foundHeaders["expiryTimestamp"] && p.ExpiryTimestamp == 0 {
		p.UnlimitedExpiry = true
	}
	p.IsPasswordSet = p.foundHeaders["password"]
	return nil
}

type paramFolderDelete struct {
	Id           string `header:"id" required:"true"`
	foundHeaders map[string]bool
}

func (p *paramFolderDelete) ProcessParameter(_ *http.Request) error {
	return nil
}

// paramFolderModify is paramFilesModify for a folder: same header names, the same "absent header
// leaves the field untouched" and "present header with a zero value means unlimited" conventions,
// and the same explicit RemovePassword signal, so a caller that already knows how to edit a file's
// own settings needs nothing new to learn. See paramFilesModify's comment for the password
// reasoning, which applies here unchanged.
//
// Unlike paramFolderCreate, name is optional: a request that only changes the expiry must not have
// to resend the name it is not touching. An empty value is not a rename to nothing - a folder can
// never legitimately have an empty name (see models.FileBundle.DisplayName) - and is refused in
// apiFolderModify.
type paramFolderModify struct {
	Id                 string `header:"id" required:"true"`
	Name               string `header:"name" supportBase64:"true"`
	AllowedDownloads   int    `header:"allowedDownloads"`
	ExpiryTimestamp    int64  `header:"expiryTimestamp"`
	Password           string `header:"password" supportBase64:"true"`
	GeneratedPassword  bool   `header:"generatedpassword"`
	RemovePassword     bool   `header:"removePassword"`
	UnlimitedDownloads bool
	UnlimitedExpiry    bool
	IsNameSet          bool
	IsPasswordSet      bool
	foundHeaders       map[string]bool
}

func (p *paramFolderModify) ProcessParameter(_ *http.Request) error {
	if p.foundHeaders["allowedDownloads"] && p.AllowedDownloads == 0 {
		p.UnlimitedDownloads = true
	}
	if p.foundHeaders["expiryTimestamp"] && p.ExpiryTimestamp == 0 {
		p.UnlimitedExpiry = true
	}
	p.IsNameSet = p.foundHeaders["name"]
	p.IsPasswordSet = p.foundHeaders["password"]
	if p.IsPasswordSet && p.RemovePassword {
		return errors.New("cannot set both password and removePassword")
	}
	return nil
}

// paramFolderShareKey carries the ID parsed out of GET /folder/{id}/sharekey. No header fields,
// so the code generator emits a ParseRequest that only calls ProcessParameter (see
// paramFilesShareKey above, which this mirrors exactly).
type paramFolderShareKey struct {
	Id string
}

func (p *paramFolderShareKey) ProcessParameter(r *http.Request) error {
	url := parseRequestUrl(r)
	trimmed := strings.TrimPrefix(url, "/folder/")
	if !strings.HasSuffix(trimmed, "/sharekey") {
		return errors.New("invalid request")
	}
	id := strings.TrimSuffix(trimmed, "/sharekey")
	if id == "" {
		return errors.New("invalid request")
	}
	p.Id = id
	return nil
}

type paramURequestSave struct {
	Id            string `header:"id"`
	Name          string `header:"name" supportBase64:"true"`
	Notes         string `header:"notes" supportBase64:"true"`
	Expiry        int64  `header:"expiry"`
	MaxFiles      int    `header:"maxfiles"`
	MaxSizeMb     int    `header:"maxsize"`
	Closed        bool   `header:"closed"`
	IsNameSet     bool
	IsExpirySet   bool
	IsMaxFilesSet bool
	IsMaxSizeSet  bool
	IsNotesSet    bool
	IsClosedSet   bool

	foundHeaders map[string]bool
}

func (p *paramURequestSave) ProcessParameter(_ *http.Request) error {
	if p.foundHeaders["name"] {
		p.IsNameSet = true
	}
	if p.foundHeaders["expiry"] {
		p.IsExpirySet = true
	}
	if p.foundHeaders["maxfiles"] {
		p.IsMaxFilesSet = true
	}
	if p.foundHeaders["maxsize"] {
		p.IsMaxSizeSet = true
	}
	if p.foundHeaders["notes"] {
		p.IsNotesSet = true
	}
	if p.foundHeaders["closed"] {
		p.IsClosedSet = true
	}
	return nil
}

type paramURequestComplete struct {
	Id           string `header:"id" required:"true"`
	foundHeaders map[string]bool
}

func (p *paramURequestComplete) ProcessParameter(_ *http.Request) error {
	return nil
}

type paramURequestListSingle struct {
	Id string
}

func (p *paramURequestListSingle) ProcessParameter(r *http.Request) error {
	url := parseRequestUrl(r)
	p.Id = strings.TrimPrefix(url, "/uploadrequest/list/")
	return nil
}

func checkHeaderExists(r *http.Request, key string, isRequired, isString bool) (bool, error) {
	if r.Header.Get(key) != "" {
		return true, nil
	}
	if isRequired {
		return false, errors.New("header " + key + " is required")
	}
	if isString {
		return len(r.Header.Values(key)) > 0, nil
	}
	return false, nil
}

func parseHeaderBool(r *http.Request, key string) (bool, error) {
	value, err := strconv.ParseBool(r.Header.Get(key))
	if err != nil {
		return false, err
	}
	return value, nil
}

func parseHeaderInt64(r *http.Request, key string) (int64, error) {
	value, err := strconv.ParseInt(r.Header.Get(key), 10, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func parseHeaderInt(r *http.Request, key string) (int, error) {
	value, err := strconv.Atoi(r.Header.Get(key))
	if err != nil {
		return 0, err
	}
	return value, nil
}
