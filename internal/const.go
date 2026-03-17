package internal

const PlaceholderFile = "placeholder.jpg"

const (
	SessionKeyUserID         = "LoggedInUserID"
	SessionKeyClientID       = "ClientID"
	SessionKeyScopeRequested = "scopeRequested"
	SessionKeyScopeConsented = "scopeConsented"
	SessionKeyResponseType   = "responseType"
	SessionKeyTelegramData   = "telegramData"
	SessionKeyNext           = "next"
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

	// Admin paths (singular 'client' to match router)
	PathAdminClients    = "/admin/client"
	PathAdminClientNew  = "/admin/client/new"
	PathAdminClientEdit = "/admin/client/edit"   // query param id
	PathAdminClientDel  = "/admin/client/delete" // query param id
)

// 登录页 next 参数
const (
	NextAuth  = "auth"
	NextAdmin = "admin"
)
