import React from 'react'
import { Users as UsersIcon } from 'lucide-react'
import ResourcePage from './ResourcePage.jsx'
import { createUser, deleteUser, getUsers, updateUser } from '../api/client.js'

const defaults = {
  impi: '',
  impu: '',
  mcptt_id: '',
  display_name: '',
  enabled: true,
}

export default function Users() {
  return (
    <ResourcePage
      title="Users"
      subtitle="MCX user identities and MCPTT IDs"
      emptyIcon={<UsersIcon size={36} />}
      listFn={getUsers}
      createFn={createUser}
      updateFn={updateUser}
      deleteFn={deleteUser}
      defaults={defaults}
      fields={[
        { key: 'display_name', label: 'Display Name', required: true },
        { key: 'impi', label: 'IMPI', mono: true, required: true },
        { key: 'impu', label: 'IMPU', mono: true, required: true },
        { key: 'mcptt_id', label: 'MCPTT ID', mono: true, required: true },
        { key: 'enabled', label: 'State', type: 'checkbox' },
      ]}
      columns={[
        { key: 'display_name', label: 'Name' },
        { key: 'mcptt_id', label: 'MCPTT ID', mono: true },
        { key: 'impi', label: 'IMPI', mono: true },
        { key: 'enabled', label: 'State', badge: true },
      ]}
    />
  )
}
