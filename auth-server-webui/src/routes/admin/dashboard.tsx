export default function Dashboard() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card bg-base-200 shadow">
          <div className="card-body">
            <h2 className="card-title">Users</h2>
            <p>Manage user accounts</p>
            <div className="card-actions">
              <a className="btn btn-primary btn-sm" href="/admin/users">Manage</a>
            </div>
          </div>
        </div>
        <div className="card bg-base-200 shadow">
          <div className="card-body">
            <h2 className="card-title">Clients</h2>
            <p>Manage OAuth2 clients</p>
            <div className="card-actions">
              <a className="btn btn-primary btn-sm" href="/admin/clients">Manage</a>
            </div>
          </div>
        </div>
        <div className="card bg-base-200 shadow">
          <div className="card-body">
            <h2 className="card-title">Admins</h2>
            <p>Manage admin users</p>
            <div className="card-actions">
              <a className="btn btn-primary btn-sm" href="/admin/admins">Manage</a>
            </div>
          </div>
        </div>
        <div className="card bg-base-200 shadow">
          <div className="card-body">
            <h2 className="card-title">Sessions</h2>
            <p>View active sessions</p>
            <div className="card-actions">
              <a className="btn btn-primary btn-sm" href="/admin/sessions">Manage</a>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
