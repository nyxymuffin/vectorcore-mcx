import React from 'react'
import { Activity, Radio, Users, FolderTree, Link2, RefreshCw, XCircle, Smartphone, PhoneCall, Mic2 } from 'lucide-react'
import StatCard from '../components/StatCard.jsx'
import Spinner from '../components/Spinner.jsx'
import { usePoller } from '../hooks/usePoller.js'
import { getStatus } from '../api/client.js'

function formatUptime(s) {
  if (s == null || Number.isNaN(s)) return '-'
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

export default function Dashboard() {
  const { data: status, error, loading, refresh } = usePoller(getStatus, 5000)

  if (loading) return <div className="loading-center"><Spinner size="lg" /><span>Loading dashboard...</span></div>
  if (error && !status) return (
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
          <div className="page-title">Dashboard</div>
          <div className="page-subtitle">VectorCore MCX Application Server</div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={refresh}><RefreshCw size={13} /></button>
      </div>

      <div className="stats-grid">
        <StatCard title="Users" value={status?.user_count ?? 0} icon={<Users size={18} />} color="var(--accent)" subtitle="MCX identities" />
        <StatCard title="Groups" value={status?.group_count ?? 0} icon={<FolderTree size={18} />} color="var(--success)" subtitle="GMS records" />
        <StatCard title="Memberships" value={status?.memberships ?? 0} icon={<Link2 size={18} />} color="var(--warning)" subtitle="static group access" />
        <StatCard title="Online Clients" value={status?.registrations?.registered_clients ?? 0} icon={<Smartphone size={18} />} color="var(--success)" subtitle="MCPTT registered" />
        <StatCard title="Active Calls" value={status?.calls?.active_calls ?? 0} icon={<PhoneCall size={18} />} color="var(--accent)" subtitle="INVITE dialogs" />
        <StatCard title="RTP Active" value={status?.calls?.active_rtp_calls ?? 0} icon={<Activity size={18} />} color="var(--success)" subtitle={`${status?.calls?.total_rtp_packets ?? 0} packets`} />
        <StatCard title="Floor Granted" value={status?.calls?.floor_granted_calls ?? 0} icon={<Mic2 size={18} />} color="var(--warning)" subtitle="SDP or floor control" />
        <StatCard title="SIP Dialogs" value={status?.calls?.sip_dialogs ?? 0} icon={<Radio size={18} />} color="var(--info)" subtitle="tracked" />
      </div>

      <div className="table-container">
        <table>
          <tbody>
            <tr><th>SIP Identity</th><td className="mono">{status?.sip_identity}</td></tr>
            <tr><th>Server Name</th><td className="mono">{status?.server_name}</td></tr>
            <tr><th>IMS Realm</th><td className="mono">{status?.ims_realm}</td></tr>
            <tr><th>Registered Users</th><td>{status?.registrations?.registered_users ?? 0}</td></tr>
            <tr><th>Recently Unregistered</th><td>{status?.registrations?.unregistered_recent ?? 0}</td></tr>
            <tr><th>Established Calls</th><td>{status?.calls?.established_calls ?? 0}</td></tr>
            <tr><th>Early Calls</th><td>{status?.calls?.early_calls ?? 0}</td></tr>
            <tr><th>Terminating Calls</th><td>{status?.calls?.terminating_calls ?? 0}</td></tr>
            <tr><th>Terminated Total</th><td>{status?.calls?.terminated_calls_total ?? 0}</td></tr>
            <tr><th>Recently Ended Calls</th><td>{status?.calls?.recently_ended ?? 0}</td></tr>
            <tr><th>RTP Bytes</th><td>{status?.calls?.total_rtp_bytes ?? 0}</td></tr>
            <tr><th>RTP Lost Packets</th><td>{status?.calls?.total_rtp_lost_packets ?? 0}</td></tr>
            <tr><th>Max RTP Jitter</th><td>{status?.calls?.max_rtp_jitter ? Number(status.calls.max_rtp_jitter).toFixed(1) : '0.0'}</td></tr>
            <tr><th>Last Media</th><td>{status?.calls?.last_media_at ? new Date(status.calls.last_media_at).toLocaleString() : '-'}</td></tr>
            <tr><th>Last BYE</th><td>{status?.calls?.last_bye_at ? new Date(status.calls.last_bye_at).toLocaleString() : '-'}</td></tr>
            <tr><th>Uptime</th><td><Radio size={13} style={{ marginRight: 6, verticalAlign: -2 }} />{formatUptime(status?.uptime_sec)}</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  )
}
