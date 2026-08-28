package models

// AuthenticationConfig holds configuration on how to authenticate to Gokapi admin menu
type AuthenticationConfig struct {
	Method int `json:"Method"`
	// deprecated, only used for migration
	SaltAdmin string `json:"SaltAdmin"`
	// deprecated, only used for migration
	SaltFiles                     string   `json:"SaltFiles"`
	Username                      string   `json:"Username"`
	HeaderKey                     string   `json:"HeaderKey"`
	OAuthProvider                 string   `json:"OauthProvider"`
	OAuthClientId                 string   `json:"OAuthClientId"`
	OAuthClientSecret             string   `json:"OAuthClientSecret"`
	OAuthGroupScope               string   `json:"OauthGroupScope"`
	OAuthRecheckInterval          int      `json:"OAuthRecheckInterval"`
	OAuthGroups                   []string `json:"OAuthGroups"`
	OnlyRegisteredUsers           bool     `json:"OnlyRegisteredUsers"`
	OAuthEnabledAlongsideInternal bool     `json:"OAuthEnabledAlongsideInternal"`
	// AllowHybridSelfRegistration is a dangerous, deliberately-not-always-serialized opt-in
	// (note the omitempty) that lets an operator override the normally-forced
	// OnlyRegisteredUsers=true in hybrid mode (internal auth with OAuth enabled alongside it).
	// Setting this to true means ANY account from the configured OAuth provider can
	// self-provision a user in this Gokapi instance. Only enable this if that is genuinely
	// intended, for example when OAuthGroups or a provider-side allow-list already restricts who
	// can authenticate.
	AllowHybridSelfRegistration bool `json:"AllowHybridSelfRegistration,omitempty"`
}

const (
	// AuthenticationInternal authentication method uses a user / password combination handled by Gokapi
	AuthenticationInternal = iota

	// AuthenticationOAuth2 authentication retrieves the users email with Open Connect ID
	AuthenticationOAuth2

	// AuthenticationHeader authentication relies on a header from a reverse proxy to parse the username
	AuthenticationHeader

	// AuthenticationDisabled authentication ignores all internal authentication procedures. A reverse proxy needs to restrict access
	AuthenticationDisabled
)
