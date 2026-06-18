import React, { useMemo, useState } from 'react'
import { PhoneCall, RefreshCw, XCircle } from 'lucide-react'
import Badge from '../components/Badge.jsx'
import Spinner from '../components/Spinner.jsx'
import { usePoller } from '../hooks/usePoller.js'
import { getCalls } from '../api/client.js'

function fmt(v) {
  if (!v) return '-'
  const d = new Date(v)
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1970) return '-'
  return d.toLocaleString()
}

function fmtRtp(row) {
  const parts = []
  if (row.rtp_payload_type !== undefined) parts.push(`PT ${row.rtp_payload_type}`)
  if (row.rtp_ssrc) parts.push(`SSRC ${row.rtp_ssrc}`)
  if (row.rtp_last_sequence) parts.push(`seq ${row.rtp_last_sequence}`)
  if (row.rtp_lost_packets) parts.push(`lost ${row.rtp_lost_packets}`)
  if (row.rtp_jitter) parts.push(`jitter ${Number(row.rtp_jitter).toFixed(1)}`)
  return parts.length ? parts.join(' / ') : '-'
}

function fmtFloor(row) {
  const parts = []
  if (row.floor_state) parts.push(row.floor_state === 'granted' && row.floor_last_event === 'sdp_granted' ? 'granted by SDP' : row.floor_state)
  if (row.floor_last_event) parts.push(row.floor_last_event)
  if (row.floor_ssrc) parts.push(`SSRC ${row.floor_ssrc}`)
  return parts.length ? parts.join(' / ') : '-'
}

function fmtLastMedia(row) {
  const times = [row.last_rtp_at, row.last_rtcp_at, row.last_floor_at]
    .map(v => v ? new Date(v) : null)
    .filter(v => v && !Number.isNaN(v.getTime()) && v.getFullYear() >= 1970)
  if (!times.length) return '-'
  return new Date(Math.max(...times.map(v => v.getTime()))).toLocaleString()
}

export default function Calls() {
  const { data, error, loading, refresh } = usePoller(getCalls, 3000)
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState('updated_at')
  const rows = Array.isArray(data) ? data : []
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = q ? rows.filter(row => JSON.stringify(row).toLowerCase().includes(q)) : rows
    return [...filtered].sort((a, b) => String(b[sort] || '').localeCompare(String(a[sort] || '')))
  }, [rows, query, sort])

  if (loading) return <div className="loading-center"><Spinner size="lg" /><span>Loading calls...</span></div>
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
          <div className="page-title">Calls</div>
          <div className="page-subtitle">MCPTT INVITE and dialog state</div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={refresh}><RefreshCw size={13} /></button>
      </div>

      <div className="flex gap-8 mb-16">
        <input className="input" style={{ maxWidth: 360 }} placeholder="Filter..." value={query} onChange={e => setQuery(e.target.value)} />
        <select className="select" style={{ maxWidth: 220 }} value={sort} onChange={e => setSort(e.target.value)}>
          <option value="state">state</option>
          <option value="updated_at">updated_at</option>
          <option value="created_at">created_at</option>
          <option value="call_id">call_id</option>
          <option value="initiator_uri">initiator_uri</option>
        </select>
        <span className="text-muted text-sm" style={{ alignSelf: 'center' }}>{visible.length}</span>
      </div>

      {rows.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon"><PhoneCall size={36} /></div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>No calls</div>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Call-ID</th>
                <th>State</th>
                <th>Initiator</th>
                <th>Target</th>
                <th>Audio</th>
                <th>Floor Control</th>
                <th>Floor State</th>
                <th>Packets</th>
                <th>RTP Stream</th>
                <th>Last Media</th>
                <th>Remote Target</th>
                <th>Answered</th>
                <th>Established</th>
                <th>Terminated</th>
                <th>Source</th>
                <th>Transport</th>
              </tr>
            </thead>
            <tbody>
              {visible.map(row => (
                <tr key={row.call_id}>
                  <td className="mono text-muted">{row.call_id || '-'}</td>
                  <td><Badge state={row.state || 'unknown'} /></td>
                  <td className="mono text-muted">{row.initiator_uri || row.mcptt_id || '-'}</td>
                  <td className="mono text-muted">{row.group_uri || row.target_uri || '-'}</td>
                  <td className="mono text-muted">{row.audio_port ? `${row.audio_ip || '-'}:${row.audio_port} ${row.audio_proto || ''}` : '-'}</td>
                  <td className="mono text-muted">{row.floor_control_port ? `${row.floor_control_ip || '-'}:${row.floor_control_port} ${row.floor_control_proto || ''}` : '-'}</td>
                  <td className="mono text-muted">{fmtFloor(row)}</td>
                  <td className="mono text-muted">{`${row.rtp_packets || 0} RTP / ${row.rtcp_packets || 0} RTCP / ${row.floor_packets || 0} floor`}</td>
                  <td className="mono text-muted">{fmtRtp(row)}</td>
                  <td>{fmtLastMedia(row)}</td>
                  <td className="mono text-muted">{row.remote_target || '-'}</td>
                  <td>{fmt(row.answered_at)}</td>
                  <td>{fmt(row.established_at)}</td>
                  <td>{fmt(row.terminated_at)}</td>
                  <td className="mono text-muted">{row.source_addr || '-'}</td>
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
