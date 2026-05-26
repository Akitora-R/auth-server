import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import type { AuthClient } from '../../types'

export default function ClientsPage() {
  const [clients, setClients] = useState<AuthClient[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
  const [scopesStr, setScopesStr] = useState('')
  const [tokenType, setTokenType] = useState(1)
  const [secret, setSecret] = useState('')

  const loadClients = async () => {
    try {
      const data = await api.getClients()
      setClients(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadClients() }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    const scopes = scopesStr.split(',').map(s => s.trim()).filter(Boolean)
    try {
      const result = await api.createClient({ display_name: name, domain, secret, scopes, token_type: tokenType })
      setShowForm(false)
      setName(''); setDomain(''); setScopesStr(''); setSecret('')
      if (result?.secret) alert('Generated secret: ' + result.secret)
      await loadClients()
    } catch (err) {
      console.error(err)
    }
  }

  const handleDelete = async (id: number) => {
    if (!confirm('Delete this client?')) return
    await api.deleteClient(id)
    await loadClients()
  }

  if (loading) return <span className="loading loading-spinner loading-lg" />

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Clients</h1>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : 'New Client'}
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="card bg-base-200 p-4 mb-4 space-y-3">
          <input className="input input-bordered w-full" placeholder="Display Name" required
            value={name} onChange={(e) => setName(e.target.value)} />
          <input className="input input-bordered w-full" placeholder="Domain (redirect URI)" required
            value={domain} onChange={(e) => setDomain(e.target.value)} />
          <input className="input input-bordered w-full" placeholder="Scopes (comma-separated)"
            value={scopesStr} onChange={(e) => setScopesStr(e.target.value)} />
          <input className="input input-bordered w-full" placeholder="Secret (leave empty to generate)"
            value={secret} onChange={(e) => setSecret(e.target.value)} />
          <select className="select select-bordered w-full" value={tokenType} onChange={(e) => setTokenType(Number(e.target.value))}>
            <option value={0}>Opaque Token</option>
            <option value={1}>JWT</option>
          </select>
          <button className="btn btn-primary" type="submit">Create</button>
        </form>
      )}

      <div className="overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Domain</th>
              <th>Scopes</th>
              <th>Token Type</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {clients.map((c) => (
              <tr key={c.id}>
                <td>{c.id}</td>
                <td>{c.display_name}</td>
                <td>{c.domain}</td>
                <td>{(c.scopes || []).join(', ')}</td>
                <td>{c.token_type === 1 ? 'JWT' : 'Opaque'}</td>
                <td>
                  <button className="btn btn-error btn-xs" onClick={() => handleDelete(c.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
