import React, { useCallback, useMemo, useState } from 'react'
import { Edit3, Plus, RefreshCw, Trash2, XCircle } from 'lucide-react'
import Badge from '../components/Badge.jsx'
import DiscardConfirm from '../components/DiscardConfirm.jsx'
import Modal from '../components/Modal.jsx'
import Spinner from '../components/Spinner.jsx'
import { useToast } from '../components/Toast.jsx'
import { useConfirmClose } from '../hooks/useConfirmClose.js'
import { useDirtyState } from '../hooks/useDirtyState.js'
import { usePoller } from '../hooks/usePoller.js'

export default function ResourcePage({ title, subtitle, emptyIcon, fields, columns, listFn, createFn, updateFn, deleteFn, defaults, filterFn }) {
  const toast = useToast()
  const { data, error, loading, refresh } = usePoller(listFn, 8000)
  const [query, setQuery] = useState('')
  const [editTarget, setEditTarget] = useState(null)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [busy, setBusy] = useState(false)

  const rows = Array.isArray(data) ? data : []
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return rows
    if (filterFn) return rows.filter(row => filterFn(row, q))
    return rows.filter(row => JSON.stringify(row).toLowerCase().includes(q))
  }, [rows, query, filterFn])

  const remove = useCallback(async () => {
    if (!deleteTarget) return
    setBusy(true)
    try {
      await deleteFn(deleteTarget.id)
      toast.success('Deleted', deleteTarget.display_name || deleteTarget.name || deleteTarget.id)
      setDeleteTarget(null)
      refresh()
    } catch (err) {
      toast.error('Delete failed', err.message)
    } finally {
      setBusy(false)
    }
  }, [deleteFn, deleteTarget, refresh, toast])

  if (loading) return <div className="loading-center"><Spinner size="lg" /><span>Loading {title.toLowerCase()}...</span></div>
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
          <div className="page-title">{title}</div>
          <div className="page-subtitle">{subtitle}</div>
        </div>
        <div className="flex gap-8">
          <button className="btn btn-ghost btn-sm" onClick={refresh}><RefreshCw size={13} /></button>
          <button className="btn btn-primary btn-sm" onClick={() => setEditTarget({})}><Plus size={12} /> Add</button>
        </div>
      </div>

      <div className="flex gap-8 mb-16">
        <input className="input" style={{ maxWidth: 360 }} placeholder="Filter..." value={query} onChange={e => setQuery(e.target.value)} />
        <span className="text-muted text-sm" style={{ alignSelf: 'center' }}>{filtered.length}{query ? ` of ${rows.length}` : ''}</span>
      </div>

      {rows.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">{emptyIcon}</div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>No records</div>
          <button className="btn btn-primary btn-sm mt-12" onClick={() => setEditTarget({})}><Plus size={12} /> Add</button>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead><tr>{columns.map(c => <th key={c.key}>{c.label}</th>)}<th>Actions</th></tr></thead>
            <tbody>
              {filtered.map(row => (
                <tr key={row.id}>
                  {columns.map(c => <td key={c.key}>{renderCell(row, c)}</td>)}
                  <td>
                    <div className="flex gap-6">
                      <button className="btn-icon" title="Edit" onClick={() => setEditTarget(row)}><Edit3 size={13} /></button>
                      <button className="btn-icon danger" title="Delete" onClick={() => setDeleteTarget(row)}><Trash2 size={13} /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editTarget && (
        <EditModal
          title={editTarget.id ? `Edit ${title}` : `Add ${title}`}
          initial={editTarget.id ? editTarget : defaults}
          fields={fields}
          createFn={createFn}
          updateFn={updateFn}
          onClose={() => setEditTarget(null)}
          onSaved={() => { setEditTarget(null); refresh() }}
        />
      )}
      {deleteTarget && (
        <Modal title="Delete Record" onClose={() => setDeleteTarget(null)}>
          <div className="modal-body">Delete <span className="mono">{deleteTarget.display_name || deleteTarget.name || deleteTarget.id}</span>?</div>
          <div className="modal-footer">
            <button className="btn btn-ghost" onClick={() => setDeleteTarget(null)}>Cancel</button>
            <button className="btn btn-danger" disabled={busy} onClick={remove}>{busy ? <Spinner size="sm" /> : null} Delete</button>
          </div>
        </Modal>
      )}
    </div>
  )
}

function renderCell(row, col) {
  if (col.render) return col.render(row)
  const v = row[col.key]
  if (col.badge) return <Badge state={v ? 'enabled' : 'disabled'} />
  if (col.mono) return <span className="mono text-muted">{v || '-'}</span>
  return v || '-'
}

function EditModal({ title, initial, fields, createFn, updateFn, onClose, onSaved }) {
  const toast = useToast()
  const [form, setForm, dirty] = useDirtyState({ ...initial })
  const [submitting, setSubmitting] = useState(false)
  const set = useCallback((k, v) => setForm(p => ({ ...p, [k]: v })), [])
  const { requestClose: guardedClose, confirming, confirmDiscard, cancelDiscard } = useConfirmClose(dirty, onClose)

  const submit = useCallback(async e => {
    e.preventDefault()
    setSubmitting(true)
    try {
      if (form.id) {
        await updateFn(form.id, form)
        toast.success('Updated')
      } else {
        await createFn(form)
        toast.success('Created')
      }
      onSaved()
    } catch (err) {
      toast.error('Save failed', err.message)
    } finally {
      setSubmitting(false)
    }
  }, [createFn, form, onSaved, toast, updateFn])

  return (
    <Modal title={title} onClose={guardedClose} size="lg" closeOnBackdrop={false} closeOnEscape={false}>
      <form onSubmit={submit}>
        <div className="modal-body">
          {fields.map(field => (
            <div className="form-group" key={field.key}>
              <label className="form-label">{field.label}</label>
              {field.type === 'textarea' ? (
                <textarea className="input mono" rows={field.rows || 8} value={form[field.key] || ''} onChange={e => set(field.key, e.target.value)} />
              ) : field.type === 'checkbox' ? (
                <label className="checkbox-wrap"><input type="checkbox" checked={!!form[field.key]} onChange={e => set(field.key, e.target.checked)} /><span>{field.checkboxLabel || 'Enabled'}</span></label>
              ) : field.type === 'select' ? (
                <select className={`select${field.mono ? ' mono' : ''}`} value={form[field.key] || ''} onChange={e => set(field.key, e.target.value)} required={field.required}>
                  {field.placeholder ? <option value="">{field.placeholder}</option> : null}
                  {(field.options || []).map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              ) : (
                <input className={`input${field.mono ? ' mono' : ''}`} value={form[field.key] || ''} onChange={e => set(field.key, e.target.value)} required={field.required} placeholder={field.placeholder || ''} />
              )}
            </div>
          ))}
        </div>
        <div className="modal-footer">
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={submitting}>{submitting ? <Spinner size="sm" /> : null} Save</button>
        </div>
      </form>
      <DiscardConfirm open={confirming} onDiscard={confirmDiscard} onCancel={cancelDiscard} />
    </Modal>
  )
}
