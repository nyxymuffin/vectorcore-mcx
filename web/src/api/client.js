const BASE = '/api/v1'

async function request(method, path, body) {
  const opts = { method, headers: {} }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(`${BASE}${path}`, opts)
  if (res.status === 204) return null
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const data = await res.json()
      msg = data.detail || data.message || data.error || msg
    } catch { /* ignore */ }
    throw new Error(msg)
  }
  const text = await res.text()
  return text ? JSON.parse(text) : null
}

export const getStatus = () => request('GET', '/status')
export const getRegistrations = () => request('GET', '/registrations')
export const getRegistrationSummary = () => request('GET', '/registrations/summary')
export const getCalls = () => request('GET', '/calls')
export const getCallSummary = () => request('GET', '/calls/summary')

export const getUsers = () => request('GET', '/users')
export const createUser = data => request('POST', '/users', data)
export const updateUser = (id, data) => request('PUT', `/users/${id}`, data)
export const deleteUser = id => request('DELETE', `/users/${id}`)

export const getGroups = () => request('GET', '/groups')
export const createGroup = data => request('POST', '/groups', data)
export const updateGroup = (id, data) => request('PUT', `/groups/${id}`, data)
export const deleteGroup = id => request('DELETE', `/groups/${id}`)

export const getMemberships = () => request('GET', '/memberships')
export const createMembership = data => request('POST', '/memberships', data)
export const updateMembership = (id, data) => request('PUT', `/memberships/${id}`, data)
export const deleteMembership = id => request('DELETE', `/memberships/${id}`)

export const getGroupAffiliations = () => request('GET', '/group-affiliations')
export const createGroupAffiliation = data => request('POST', '/group-affiliations', data)
export const updateGroupAffiliation = (id, data) => request('PUT', `/group-affiliations/${id}`, data)
export const deleteGroupAffiliation = id => request('DELETE', `/group-affiliations/${id}`)
