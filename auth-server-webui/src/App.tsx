import { Routes, Route, Link, useLocation, Navigate } from 'react-router'
import { AuthProvider, useAuth } from './lib/auth'
import { api } from './lib/api'
import { useEffect } from 'react'
import Dashboard from './routes/admin/dashboard'
import UsersPage from './routes/admin/users'
import ClientsPage from './routes/admin/clients'
import AdminsPage from './routes/admin/admins'
import SessionsPage from './routes/admin/sessions'

function CallbackPage() {
  const { handleCallback } = useAuth()
  const params = new URLSearchParams(window.location.search)
  const code = params.get('code')
  const state = params.get('state')

  useEffect(() => {
    if (code && state) {
      handleCallback(code, state).then((ok) => {
        window.location.href = ok ? '/admin' : '/login'
      })
    }
  }, [code, state, handleCallback])

  return <div className="flex items-center justify-center h-screen">
    <span className="loading loading-spinner loading-lg" />
  </div>
}

function LoginPage() {
  const { login } = useAuth()
  return (
    <div className="flex flex-col items-center justify-center h-screen gap-4">
      <h1 className="text-3xl font-bold">Auth Server Admin</h1>
      <p className="text-base-content/60">Sign in to manage OAuth2 clients and users</p>
      <button className="btn btn-primary btn-lg" onClick={login}>Sign in with Auth Server</button>
    </div>
  )
}

function AdminLayout() {
  const { isAuthenticated, accessToken, logout } = useAuth()
  const location = useLocation()

  useEffect(() => {
    api.setToken(accessToken)
  }, [accessToken])

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  const navItems = [
    { to: '/admin', label: 'Dashboard' },
    { to: '/admin/users', label: 'Users' },
    { to: '/admin/clients', label: 'Clients' },
    { to: '/admin/admins', label: 'Admins' },
    { to: '/admin/sessions', label: 'Sessions' },
  ]

  return (
    <div className="drawer lg:drawer-open">
      <input id="main-drawer" type="checkbox" className="drawer-toggle" />
      <div className="drawer-content flex flex-col min-h-screen">
        <div className="navbar bg-base-300">
          <div className="flex-none lg:hidden">
            <label htmlFor="main-drawer" className="btn btn-square btn-ghost drawer-button">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" className="inline-block h-5 w-5 stroke-current">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </label>
          </div>
          <div className="flex-1">
            <Link to="/admin" className="btn btn-ghost text-xl">Auth Server Admin</Link>
          </div>
          <div className="flex-none">
            <button className="btn btn-ghost" onClick={logout}>Logout</button>
          </div>
        </div>
        <div className="p-4 flex-1">
          <Routes>
            <Route index element={<Dashboard />} />
            <Route path="users" element={<UsersPage />} />
            <Route path="clients" element={<ClientsPage />} />
            <Route path="admins" element={<AdminsPage />} />
            <Route path="sessions" element={<SessionsPage />} />
          </Routes>
        </div>
      </div>
      <div className="drawer-side">
        <label htmlFor="main-drawer" aria-label="close sidebar" className="drawer-overlay" />
        <ul className="menu bg-base-200 text-base-content min-h-full w-60 p-4">
          {navItems.map((item) => (
            <li key={item.to}>
              <Link to={item.to} className={location.pathname === item.to ? 'active' : ''}>
                {item.label}
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/callback" element={<CallbackPage />} />
        <Route path="/admin/*" element={<AdminLayout />} />
        <Route path="*" element={<Navigate to="/admin" replace />} />
      </Routes>
    </AuthProvider>
  )
}
