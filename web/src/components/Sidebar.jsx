import React from 'react'
import { NavLink } from 'react-router-dom'
import { FolderTree, LayoutDashboard, Link2, PhoneCall, Smartphone, Users } from 'lucide-react'

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
  { to: '/users', label: 'Users', icon: <Users size={16} /> },
  { to: '/groups', label: 'Groups', icon: <FolderTree size={16} /> },
  { to: '/memberships', label: 'Memberships', icon: <Link2 size={16} /> },
  { to: '/registrations', label: 'Registrations', icon: <Smartphone size={16} /> },
  { to: '/calls', label: 'Calls', icon: <PhoneCall size={16} /> },
]

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">VectorCore</div>
        <div className="sidebar-logo-sub">MCX AS</div>
      </div>
      <nav className="sidebar-nav" aria-label="Primary navigation">
        {NAV_ITEMS.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            {icon}
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar-footer" />
    </aside>
  )
}
