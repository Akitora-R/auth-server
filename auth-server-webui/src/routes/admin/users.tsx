import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import type { User } from '../../types'

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')

  const loadUsers = async () => {
    try {
      const data = await api.getUsers()
      setUsers(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadUsers() }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await api.createUser(email, displayName, password)
      setShowForm(false)
      setEmail(''); setDisplayName(''); setPassword('')
      await loadUsers()
    } catch (err) {
      console.error(err)
    }
  }

  const handleDelete = async (id: number) => {
    if (!confirm('Delete this user?')) return
    await api.deleteUser(id)
    await loadUsers()
  }

  if (loading) return <span className="loading loading-spinner loading-lg" />

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Users</h1>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : 'New User'}
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="card bg-base-200 p-4 mb-4 space-y-3">
          <input
            className="input input-bordered w-full" placeholder="Email" type="email" required
            value={email} onChange={(e) => setEmail(e.target.value)}
          />
          <input
            className="input input-bordered w-full" placeholder="Display Name"
            value={displayName} onChange={(e) => setDisplayName(e.target.value)}
          />
          <input
            className="input input-bordered w-full" placeholder="Password" type="password" required
            value={password} onChange={(e) => setPassword(e.target.value)}
          />
          <button className="btn btn-primary" type="submit">Create</button>
        </form>
      )}

      <div className="overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Email</th>
              <th>Display Name</th>
              <th>Last Login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.id}</td>
                <td>{u.email}</td>
                <td>{u.display_name}</td>
                <td>{u.last_login_at || '-'}</td>
                <td>
                  <button className="btn btn-error btn-xs" onClick={() => handleDelete(u.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
