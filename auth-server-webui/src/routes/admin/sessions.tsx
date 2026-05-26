import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import type { SessionInfo } from '../../types'

export default function SessionsPage() {
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [loading, setLoading] = useState(true)

  const loadSessions = async () => {
    try {
      const data = await api.getSessions()
      setSessions(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadSessions() }, [])

  const handleRevoke = async (userId: number) => {
    if (!confirm('Revoke all sessions for this user?')) return
    await api.revokeSession(userId)
    await loadSessions()
  }

  if (loading) return <span className="loading loading-spinner loading-lg" />

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Sessions</h1>
      <div className="overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th>User ID</th>
              <th>Email</th>
              <th>Display Name</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.user_id}>
                <td>{s.user_id}</td>
                <td>{s.email}</td>
                <td>{s.display_name}</td>
                <td>
                  <button className="btn btn-warning btn-xs" onClick={() => handleRevoke(s.user_id)}>Revoke</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
