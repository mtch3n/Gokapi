package models

// Session contains cookie parameter
type Session struct {
	RenewAt    int64 `redis:"renew_at"`
	ValidUntil int64 `redis:"valid_until"`
	UserId     int   `redis:"user_id"`
	// IsOauth records whether this session was created by the OAuth callback, so that a renewal
	// (see sessionmanager.useSession) recreates the same kind of session instead of inferring it
	// from the current global auth method - which is wrong in hybrid mode, where the method stays
	// AuthenticationInternal even for sessions the OAuth callback created.
	IsOauth bool `redis:"is_oauth"`
}
