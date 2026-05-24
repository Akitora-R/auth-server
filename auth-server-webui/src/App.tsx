import { Routes, Route, Link } from 'react-router'
import HomePage from './routes/home'
import LoginPage from './routes/login'

export default function App() {
  return (
    <div className="drawer lg:drawer-open">
      <input id="main-drawer" type="checkbox" className="drawer-toggle" />
      <div className="drawer-content flex flex-col">
        <div className="navbar bg-base-300">
          <div className="flex-none lg:hidden">
            <label htmlFor="main-drawer" className="btn btn-square btn-ghost drawer-button">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" className="inline-block h-5 w-5 stroke-current">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </label>
          </div>
          <div className="flex-1">
            <Link to="/" className="btn btn-ghost text-xl">Auth Server</Link>
          </div>
        </div>
        <div className="p-4">
          <Routes>
            <Route index element={<HomePage />} />
            <Route path="login" element={<LoginPage />} />
          </Routes>
        </div>
      </div>
      <div className="drawer-side">
        <label htmlFor="main-drawer" aria-label="close sidebar" className="drawer-overlay" />
        <ul className="menu bg-base-200 text-base-content min-h-full w-60 p-4">
          <li><Link to="/">Home</Link></li>
          <li><Link to="/login">Login</Link></li>
        </ul>
      </div>
    </div>
  )
}
