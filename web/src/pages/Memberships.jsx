import React from 'react'
import { Link2 } from 'lucide-react'
import ResourcePage from './ResourcePage.jsx'
import {
  createMembership,
  deleteMembership,
  getGroups,
  getMemberships,
  getUsers,
  updateMembership,
} from '../api/client.js'
import { usePoller } from '../hooks/usePoller.js'

export default function Memberships() {
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
      title="Memberships"
      subtitle="Static user to group authorization"
      emptyIcon={<Link2 size={36} />}
      listFn={getMemberships}
      createFn={createMembership}
      updateFn={updateMembership}
      deleteFn={deleteMembership}
      defaults={{ user_id: '', group_id: '', role: 'MCPTT User', priority: 0 }}
      fields={[
        { key: 'user_id', label: 'User', type: 'select', options: userOptions, placeholder: 'Select user', required: true },
        { key: 'group_id', label: 'Group', type: 'select', options: groupOptions, placeholder: 'Select group', required: true },
        { key: 'role', label: 'Role', type: 'select', options: [
          { value: 'MCPTT User', label: 'MCPTT User' },
          { value: 'MCPTT Dispatcher', label: 'MCPTT Dispatcher' },
          { value: 'MCPTT Administrator', label: 'MCPTT Administrator' },
          { value: 'MCPTT Supervisor', label: 'MCPTT Supervisor' },
        ], required: true },
        { key: 'priority', label: 'Priority' },
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
        { key: 'role', label: 'Role' },
        { key: 'priority', label: 'Priority' },
      ]}
    />
  )
}
