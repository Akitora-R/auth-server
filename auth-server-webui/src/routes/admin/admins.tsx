import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import type { AdminEntry } from '../../types'

export default function AdminsPage() {
  const [admins, setAdmins] = useState<AdminEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [userId, setUserId] = useState('')
  const [error, setError] = useState('')

  const loadAdmins = async () => {
    try {
      const data = await api.getAdmins()
      setAdmins(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadAdmins() }, [])

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      await api.addAdmin(Number(userId))
      setUserId('')
      await loadAdmins()
    } catch (err: any) {
      setError(err.message)
    }
  }

  const handleRemove = async (uid: number) => {
    if (!confirm('Remove this admin?')) return
    await api.removeAdmin(uid)
    await loadAdmins()
  }

  if (loading) return <span className="loading loading-spinner loading-lg" />

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Admins</h1>

      <form onSubmit={handleAdd} className="flex gap-2 mb-4">
        <input
          className="input input-bordered" placeholder="User ID" required
          value={userId} onChange={(e) => setUserId(e.target.value)}
        />
        <button className="btn btn-primary" type="submit">Add Admin</button>
      </form>
      {error && <div className="alert alert-error mb-4">{error}</div>}

      <div className="overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th>Admin ID</th>
              <th>User ID</th>
              <th>Email</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {admins.map((a) => (
              <tr key={a.id}>
                <td>{a.id}</td>
                <td>{a.user_id}</td>
                <td>{a.email}</td>
                <td>
                  <button className="btn btn-error btn-xs" onClick={() => handleRemove(a.user_id)}>Remove</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
