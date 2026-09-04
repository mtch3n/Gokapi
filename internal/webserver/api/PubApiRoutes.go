package api

// PubApiRoutes is the canonical list of every "/pubapi/*" path the server actually serves.
// Those handlers are registered directly in webserver.createMux, not through this package's own
// routes table (routing.go) - and this package cannot import webserver to read createMux back,
// since webserver already imports api, so this list is the other direction's source of truth: it
// is what lets openapi_test.go validate a documented "/pubapi/" path without either a real mux to
// query or an import cycle to get one.
//
// Two tests are what keep this list honest, and both must exist for either to mean anything:
//   - openapi_test.go's validateNoExtraPaths fails if openapi.json documents a "/pubapi/" path
//     that is not in this list, catching a spec entry for an endpoint that does not exist.
//   - webserver's TestPubApiRoutesAreAllRegistered fails if this list names a path createMux
//     does not actually register, catching the list drifting stale the other way.
//
// Update this list first - before either test - when a "/pubapi/" handler is added, renamed, or
// removed. It is deliberately every route, not only the documented ones: D30's openapi_test.go
// check is one-directional (a documented path must appear here, not the reverse), so an
// undocumented "/pubapi/" endpoint stays legal and does not need adding to openapi.json to pass.
var PubApiRoutes = []string{
	"/pubapi/config",
	"/pubapi/downloadsession",
	"/pubapi/error",
	"/pubapi/file",
	"/pubapi/filepassword",
	"/pubapi/folder",
	"/pubapi/foldersession",
	"/pubapi/folderpassword",
	"/pubapi/folderzip",
	"/pubapi/uploadrequest",
	"/pubapi/share/resend",
}
