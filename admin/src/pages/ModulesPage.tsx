import { useEffect, useState } from 'react'
import type { Module } from '../types'

interface Props {
  apiGet: <T>(path: string) => Promise<T>
  apiPost: <T>(path: string, body: unknown) => Promise<T>
  apiPut: <T>(path: string, body: unknown) => Promise<T>
  apiDelete: <T>(path: string) => Promise<T>
  addToast: (message: string, type: 'success' | 'error' | 'info') => void
}

export function ModulesPage({ apiGet, apiPost, apiPut, apiDelete, addToast }: Props) {
  const [modules, setModules] = useState<Module[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editing, setEditing] = useState<Module | null>(null)
  const [form, setForm] = useState<any>({})
  const [saving, setSaving] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const res = await apiGet<{ ok: boolean; modules: Module[] }>('/api/_admin/modules?limit=200')
      setModules(res.modules)
    } catch (e) { addToast(e instanceof Error ? e.message : 'Load failed', 'error') }
    finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [])

  const openCreate = () => { setEditing(null); setForm(defaultForm()); setShowModal(true) }
  const openEdit = (m: Module) => { setEditing(m); setForm(moduleToForm(m)); setShowModal(true) }
  const closeModal = () => { setShowModal(false); setEditing(null); setForm({}) }

  const submit = async () => {
    setSaving(true)
    try {
      if (editing) {
        await apiPut(`/api/_admin/modules/${editing.slug}`, form)
        addToast('Module updated', 'success')
      } else {
        await apiPost('/api/_admin/modules', form)
        addToast('Module created', 'success')
      }
      closeModal()
      await load()
    } catch (e) { addToast(e instanceof Error ? e.message : 'Save failed', 'error') }
    finally { setSaving(false) }
  }

  const handleDelete = async (slug: string) => {
    if (!confirm(`Delete module "${slug}" and all its builds/changelog?`)) return
    try { await apiDelete(`/api/_admin/modules/${slug}`); addToast('Deleted', 'success'); await load() }
    catch (e) { addToast(e instanceof Error ? e.message : 'Delete failed', 'error') }
  }

  if (loading) return <div className="loading"><span className="spinner" />Loading modules…</div>

  return <>
    <div className="page-header">
      <h1 className="page-title">Modules / Catalog</h1>
      <button className="btn btn-primary" onClick={openCreate}>+ Add module</button>
    </div>
    <div className="card">
      <div className="card-body" style={{ padding: 0 }}>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr><th>Slug</th><th>Title</th><th>Package</th><th>Build</th><th>ABIs</th><th>Featured</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {modules.length === 0 ? (
                <tr><td colSpan={8}><div className="empty-state"><div className="empty-icon">◈</div><div className="empty-title">No modules yet</div><div>Click "Add module" to create the first catalog entry.</div></div></td></tr>
              ) : (
                modules.map(m => (
                  <tr key={m.slug}>
                    <td><code>{m.slug}</code></td>
                    <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.title}</td>
                    <td><code>{m.package_name}</code></td>
                    <td>{m.build}</td>
                    <td>{m.abis.join(', ')}</td>
                    <td><span className={`badge ${m.featured ? 'badge-success' : 'badge-neutral'}`}>{m.featured ? 'Yes' : 'No'}</span></td>
                    <td><span className={`badge badge-${m.update_status === 'ready' ? 'success' : m.update_status === 'updating' ? 'info' : 'neutral'}`}>{m.update_status}</span></td>
                    <td style={{ whiteSpace: 'nowrap', display: 'flex', gap: 8 }}>
                      <button className="btn btn-sm btn-secondary" onClick={() => openEdit(m)}>Edit</button>
                      <button className="btn btn-sm btn-danger" onClick={() => handleDelete(m.slug)}>Delete</button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    {showModal && (
      <div className="modal-overlay" onClick={closeModal}>
        <div className="modal" onClick={e => e.stopPropagation()}>
          <div className="modal-header">
            <h2 className="modal-title">{editing ? 'Edit module' : 'New module'}</h2>
            <button className="modal-close" onClick={closeModal} aria-label="Close">✕</button>
          </div>
          <div className="modal-body">
            <form onSubmit={e => { e.preventDefault(); void submit() }}>
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">Slug (auto from package if empty)</label>
                  <input className="form-input" value={form.slug || ''} onChange={e => setForm({...form, slug: e.target.value})} placeholder="my-mod" />
                </div>
                <div className="form-group">
                  <label className="form-label">Package name *</label>
                  <input className="form-input" value={form.package_name} onChange={e => setForm({...form, package_name: e.target.value})} placeholder="com.example.mymod" required />
                </div>
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">Title *</label>
                  <input className="form-input" value={form.title} onChange={e => setForm({...form, title: e.target.value})} placeholder="My Mod" required />
                </div>
                <div className="form-group">
                  <label className="form-label">Default version</label>
                  <input className="form-input" value={form.default_version || ''} onChange={e => setForm({...form, default_version: e.target.value})} placeholder="1.0" />
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Summary</label>
                <textarea className="form-textarea" value={form.summary} onChange={e => setForm({...form, summary: e.target.value})} placeholder="Short description shown in catalog" />
              </div>
              <div className="form-group">
                <label className="form-label">Description</label>
                <textarea className="form-textarea" value={form.description} onChange={e => setForm({...form, description: e.target.value})} placeholder="Full markdown description" />
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">Versions (JSON array)</label>
                  <textarea className="form-textarea" style={{ fontFamily: 'var(--font-mono)' }} value={JSON.stringify(form.versions, null, 2)} onChange={e => { try { setForm({...form, versions: JSON.parse(e.target.value)}) } catch {} }} placeholder='["1.0", "1.1"]' />
                </div>
                <div className="form-group">
                  <label className="form-label">Version codes (JSON array)</label>
                  <textarea className="form-textarea" style={{ fontFamily: 'var(--font-mono)' }} value={JSON.stringify(form.version_codes, null, 2)} onChange={e => { try { setForm({...form, version_codes: JSON.parse(e.target.value)}) } catch {} }} placeholder='[100, 101]' />
                </div>
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">ABIs (JSON array)</label>
                  <textarea className="form-textarea" style={{ fontFamily: 'var(--font-mono)' }} value={JSON.stringify(form.abis, null, 2)} onChange={e => { try { setForm({...form, abis: JSON.parse(e.target.value)}) } catch {} }} placeholder='["arm64-v8a"]' />
                </div>
                <div className="form-group">
                  <label className="form-label">Build number</label>
                  <input className="form-input" type="number" value={form.build} onChange={e => setForm({...form, build: Number(e.target.value)})} min="1" />
                </div>
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">Tags (JSON array)</label>
                  <textarea className="form-textarea" style={{ fontFamily: 'var(--font-mono)' }} value={JSON.stringify(form.tags, null, 2)} onChange={e => { try { setForm({...form, tags: JSON.parse(e.target.value)}) } catch {} }} placeholder='["hacks", "cosmetics"]' />
                </div>
                <div className="form-group">
                  <label className="form-label">Category</label>
                  <input className="form-input" value={form.category || 'misc'} onChange={e => setForm({...form, category: e.target.value})} placeholder="misc" />
                </div>
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">Download size by ABI (JSON)</label>
                  <textarea className="form-textarea" style={{ fontFamily: 'var(--font-mono)' }} value={JSON.stringify(form.download_size_by_abi, null, 2)} onChange={e => { try { setForm({...form, download_size_by_abi: JSON.parse(e.target.value)}) } catch {} }} placeholder='{"arm64-v8a": 500000}' />
                </div>
                <div className="form-group">
                  <label className="form-label">Entry point</label>
                  <input className="form-input" value={form.entry_point || ''} onChange={e => setForm({...form, entry_point: e.target.value})} placeholder="com.example.MenuActivity" />
                </div>
              </div>
              <div className="form-row">
                <label className="form-checkbox" style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input type="checkbox" checked={form.featured} onChange={e => setForm({...form, featured: e.target.checked})} />
                  <span>Featured</span>
                </label>
                <label className="form-checkbox" style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input type="checkbox" checked={form.private_scope ? false : true} onChange={e => setForm({...form, private_scope: e.target.checked ? null : form.private_scope || 'private.scope'})} />
                  <span>Public (uncheck for private)</span>
                </label>
              </div>
              {form.private_scope && (
                <div className="form-group">
                  <label className="form-label">Private scope</label>
                  <input className="form-input" value={form.private_scope} onChange={e => setForm({...form, private_scope: e.target.value})} placeholder="beta.cheats" />
                </div>
              )}
            </form>
          </div>
          <div className="modal-footer">
            <button className="btn btn-secondary" onClick={closeModal}>Cancel</button>
            <button className="btn btn-primary" onClick={submit} disabled={saving}>{saving ? 'Saving…' : (editing ? 'Save changes' : 'Create module')}</button>
          </div>
        </div>
      </div>
    )}
  </>
}

function defaultForm() {
  return {
    slug: '', package_name: '', title: '', summary: '', description: '', developer: '',
    versions: ['1.0'], version_codes: [100], abis: ['arm64-v8a'], build: 1,
    tags: [], featured: false, category: 'misc', download_size_by_abi: {},
    default_version: '1.0', entry_point: '', private_scope: null,
  }
}

function moduleToForm(m: Module) {
  return {
    slug: m.slug, package_name: m.package_name, title: m.title, summary: m.summary,
    description: m.description, developer: m.developer || '',
    versions: m.versions, version_codes: m.version_codes, abis: m.abis, build: m.build,
    tags: m.tags, featured: !!m.featured, category: m.category, download_size_by_abi: m.download_size_by_abi,
    default_version: m.default_version, entry_point: m.entry_point, private_scope: m.private_scope,
  }
}