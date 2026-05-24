package internal

const PlaceholderFile = "placeholder.jpg"

const (
	SessionKeyUserID         = "LoggedInUserID"
	SessionKeyClientID       = "ClientID"
	SessionKeyScopeRequested = "scopeRequested"
	SessionKeyScopeConsented = "scopeConsented"
	SessionKeyResponseType   = "responseType"
	SessionKeyTelegramData   = "telegramData"
)

const (
	PathLogin        = "/login"
	PathAuth         = "/auth"
	PathAuthorize    = "/oauth2/authorize"
	PathToken        = "/oauth2/token"
	PathIntrospect   = "/introspect"
	PathUserinfo     = "/userinfo"
	PathRegistration = "/registration"
	PathDiscovery    = "/.well-known/openid-configuration"
	PathJwkSet       = "/.well-known/jwks.json"

	PathAdminClients    = "/admin/client"
	PathAdminClientNew  = "/admin/client/new"
	PathAdminClientEdit = "/admin/client/edit"
	PathAdminClientDel  = "/admin/client/delete"
)
