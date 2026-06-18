import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Users from './pages/Users.jsx'
import Groups from './pages/Groups.jsx'
import Memberships from './pages/Memberships.jsx'
import Registrations from './pages/Registrations.jsx'
import Calls from './pages/Calls.jsx'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="users" element={<Users />} />
        <Route path="groups" element={<Groups />} />
        <Route path="memberships" element={<Memberships />} />
        <Route path="affiliations" element={<Navigate to="/memberships" replace />} />
        <Route path="registrations" element={<Registrations />} />
        <Route path="calls" element={<Calls />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  )
}
