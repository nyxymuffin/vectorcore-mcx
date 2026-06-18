import React from 'react'
import { RadioTower } from 'lucide-react'
import ResourcePage from './ResourcePage.jsx'
import {
  createGroupAffiliation,
  deleteGroupAffiliation,
  getGroupAffiliations,
  getGroups,
  getUsers,
  updateGroupAffiliation,
} from '../api/client.js'
import { usePoller } from '../hooks/usePoller.js'

export default function CurrentAffiliations() {
  const { data: users } = usePoller(getUsers, 8000)
  const { data: groups } = usePoller(getGroups, 8000)
  const userRows = Array.isArray(users) ? users : []
  const groupRows = Array.isArray(groups) ? groups : []
  const userByID = new Map(userRows.map(u => [u.id, u]))
  const groupByID = new Map(groupRows.map(g => [g.id, g]))
  const userOptions = userRows.map(u => ({
    value: u.id,
    label: `${u.display_name || u.mcptt_id || u.impu || u.id} (${u.mcptt_id || u.impu || u.id})`,
  }))
  const groupOptions = groupRows.map(g => ({
    value: g.id,
    label: `${g.display_name || g.uri || g.id} (${g.uri || g.id})`,
  }))

  return (
    <ResourcePage
      title="Current Affiliations"
      subtitle="Runtime selected MCPTT group state"
      emptyIcon={<RadioTower size={36} />}
      listFn={getGroupAffiliations}
      createFn={createGroupAffiliation}
      updateFn={updateGroupAffiliation}
      deleteFn={deleteGroupAffiliation}
      defaults={{ user_id: '', group_id: '', state: 'affiliated', source: 'ui' }}
      fields={[
        { key: 'user_id', label: 'User', type: 'select', options: userOptions, placeholder: 'Select user', required: true },
        { key: 'group_id', label: 'Group', type: 'select', options: groupOptions, placeholder: 'Select group', required: true },
        { key: 'state', label: 'State', type: 'select', options: [
          { value: 'affiliated', label: 'affiliated' },
          { value: 'affiliating', label: 'affiliating' },
          { value: 'deaffiliating', label: 'deaffiliating' },
          { value: 'deaffiliated', label: 'deaffiliated' },
        ], required: true },
        { key: 'source', label: 'Source' },
      ]}
      columns={[
        { key: 'user_id', label: 'User', render: row => {
          const u = userByID.get(row.user_id)
          return <span className="mono text-muted">{u?.display_name || u?.mcptt_id || row.user_id || '-'}</span>
        } },
        { key: 'group_id', label: 'Group', render: row => {
          const g = groupByID.get(row.group_id)
          return <span className="mono text-muted">{g?.display_name || g?.uri || row.group_id || '-'}</span>
        } },
        { key: 'state', label: 'State' },
        { key: 'source', label: 'Source' },
        { key: 'expires_at', label: 'Expires At', render: row => formatDate(row.expires_at) },
      ]}
    />
  )
}

function formatDate(value) {
  if (!value) return '-'
  const d = new Date(value)
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1970) return '-'
  return d.toLocaleString()
}
