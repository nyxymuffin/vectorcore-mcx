import React, { useMemo, useState } from 'react'
import { RefreshCw, Smartphone, XCircle } from 'lucide-react'
import Badge from '../components/Badge.jsx'
import Spinner from '../components/Spinner.jsx'
import { usePoller } from '../hooks/usePoller.js'
import { getRegistrations } from '../api/client.js'

function fmt(v) {
  if (!v) return '-'
  const d = new Date(v)
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1970) return '-'
  return d.toLocaleString()
}

export default function Registrations() {
  const { data, error, loading, refresh } = usePoller(getRegistrations, 5000)
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState('last_seen_at')
  const rows = Array.isArray(data) ? data : []
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = q ? rows.filter(row => JSON.stringify(row).toLowerCase().includes(q)) : rows
    return [...filtered].sort((a, b) => String(b[sort] || '').localeCompare(String(a[sort] || '')))
  }, [rows, query, sort])

  if (loading) return <div className="loading-center"><Spinner size="lg" /><span>Loading registrations...</span></div>
  if (error && !data) return (
    <div className="error-state">
      <XCircle size={32} className="error-icon" />
      <div>{error}</div>
      <button className="btn btn-ghost mt-12" onClick={refresh}>Retry</button>
    </div>
  )

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Registrations</div>
          <div className="page-subtitle">MCPTT third-party REGISTER state</div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={refresh}><RefreshCw size={13} /></button>
      </div>

      <div className="flex gap-8 mb-16">
        <input className="input" style={{ maxWidth: 360 }} placeholder="Filter..." value={query} onChange={e => setQuery(e.target.value)} />
        <select className="select" style={{ maxWidth: 220 }} value={sort} onChange={e => setSort(e.target.value)}>
          <option value="state">state</option>
          <option value="last_registered_at">registered_at</option>
          <option value="expires_at">expires_at</option>
          <option value="public_identity">public_identity</option>
        </select>
        <span className="text-muted text-sm" style={{ alignSelf: 'center' }}>{visible.length}</span>
      </div>

      {rows.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon"><Smartphone size={36} /></div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>No registrations</div>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Public Identity</th>
                <th>IMSI / User</th>
                <th>Contact URI</th>
                <th>State</th>
                <th>Registered At</th>
                <th>Expires At</th>
                <th>Last Seen</th>
                <th>Source</th>
                <th>Transport</th>
              </tr>
            </thead>
            <tbody>
              {visible.map(row => (
                <tr key={row.public_identity}>
                  <td className="mono text-muted">{row.public_identity || '-'}</td>
                  <td className="mono text-muted">{row.imsi || row.mcptt_id || '-'}</td>
                  <td className="mono text-muted">{row.contact_uri || '-'}</td>
                  <td><Badge state={row.state || 'unknown'} /></td>
                  <td>{fmt(row.last_registered_at)}</td>
                  <td>{fmt(row.expires_at)}</td>
                  <td>{fmt(row.last_seen_at)}</td>
                  <td className="mono text-muted">{row.source_ip ? `${row.source_ip}:${row.source_port || 5060}` : '-'}</td>
                  <td><Badge state={row.transport || 'info'} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
