import React from 'react'
import { FolderTree } from 'lucide-react'
import ResourcePage from './ResourcePage.jsx'
import { createGroup, deleteGroup, getGroups, updateGroup } from '../api/client.js'

export default function Groups() {
  return (
    <ResourcePage
      title="Groups"
      subtitle="GMS group definitions used for MCPTT affiliation"
      emptyIcon={<FolderTree size={36} />}
      listFn={getGroups}
      createFn={createGroup}
      updateFn={updateGroup}
      deleteFn={deleteGroup}
      defaults={{
        uri: '',
        display_name: '',
        description: '',
        enabled: true,
      }}
      fields={[
        { key: 'display_name', label: 'Display Name', required: true },
        { key: 'uri', label: 'Group URI', mono: true, required: true },
        { key: 'description', label: 'Description' },
        { key: 'enabled', label: 'State', type: 'checkbox' },
      ]}
      columns={[
        { key: 'display_name', label: 'Name' },
        { key: 'uri', label: 'URI', mono: true },
        { key: 'description', label: 'Description' },
        { key: 'enabled', label: 'State', badge: true },
      ]}
    />
  )
}
