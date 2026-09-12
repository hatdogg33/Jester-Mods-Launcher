import { useEffect, useState } from 'react'
import type { LauncherRelease } from '../types'

interface Props {
  apiGet: <T>(path: string) => Promise<T>
  apiPost: <T>(path: string, body: unknown) => Promise<T>
  apiDelete: <T>(path: string) => Promise<T>
  addToast: (message: string, type: 'success' | 'error' | 'info') => void
}

export function ReleasesPage({ apiGet, apiPost, apiDelete, addToast }: Props) {
  const [releases, setReleases] = useState<LauncherRelease[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [form, setForm] = useState<any>(defaultForm())
  const [saving, setSaving] = useState(false)

  const load = async () => {
    setLoading(true)
    try { setReleases((await apiGet<{ releases: LauncherRelease[] }>('/api/_admin/releases')).releases) }
    catch (e) { addToast(e instanceof Error ? e.message : 'Load failed', 'error') }
    finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [])

  const submit = async () => {
    setSaving(true)
    try { await apiPost('/api/_admin/releases', form); addToast('Release published', 'success'); setShowModal(false); setForm(defaultForm()); await load() }
    catch (e) { addToast(e instanceof Error ? e.message : 'Publish failed', 'error') }
    finally { setSaving(false) }
  }
  const remove = async (build: number) => {
    if (!confirm(`Delete release ${build}?`)) return
    try { await apiDelete(`/api/_admin/releases/${build}`); addToast('Release deleted', 'success'); await load() }
    catch (e) { addToast(e instanceof Error ? e.message : 'Delete failed', 'error') }
  }

  if (loading) return <div className="loading"><span className="spinner" />Loading releases…</div>
  return <>
    <div className="page-header"><h1 className="page-title">Launcher Releases</h1><button className="btn btn-primary" onClick={() => setShowModal(true)}>+ Publish release</button></div>
    <div className="card"><div className="card-body" style={{ padding: 0 }}><div className="table-wrapper"><table>
      <thead><tr><th>Build</th><th>Version</th><th>Flavor</th><th>Channel</th><th>Size</th><th>Published</th><th>Actions</th></tr></thead>
      <tbody>{releases.length === 0 ? <tr><td colSpan={7}><div className="empty-state"><div className="empty-icon">↟</div><div className="empty-title">No releases yet</div><div>Publish an APK release to make it available to the launcher.</div></div></td></tr> : releases.map(r => <tr key={`${r.build}-${r.flavor}`}>
        <td><code>{r.build}</code></td><td>{r.version}</td><td><span className="badge badge-info">{r.flavor}</span></td><td><span className={`badge ${r.test_channel ? 'badge-warning' : 'badge-success'}`}>{r.test_channel ? 'Test' : 'Stable'}</span></td><td>{formatBytes(r.size_bytes)}</td><td>{new Date(r.published_at * 1000).toLocaleDateString()}</td><td><button className="btn btn-sm btn-danger" onClick={() => remove(r.build)}>Delete</button></td>
      </tr>)}</tbody>
    </table></div></div></div>
    {showModal && <div className="modal-overlay" onClick={() => setShowModal(false)}><div className="modal" onClick={e => e.stopPropagation()}>
      <div className="modal-header"><h2 className="modal-title">Publish launcher release</h2><button className="modal-close" onClick={() => setShowModal(false)}>✕</button></div>
      <div className="modal-body">
        <div className="form-row"><div className="form-group"><label className="form-label">Build *</label><input className="form-input" type="number" value={form.build} onChange={e => setForm({...form, build: Number(e.target.value)})} /></div><div className="form-group"><label className="form-label">Version *</label><input className="form-input" value={form.version} onChange={e => setForm({...form, version: e.target.value})} placeholder="4.1.3" /></div></div>
        <div className="form-row"><div className="form-group"><label className="form-label">Flavor</label><select className="form-select" value={form.flavor} onChange={e => setForm({...form, flavor: e.target.value})}><option value="nonroot">Non-root</option><option value="root">Root</option></select></div><div className="form-group"><label className="form-label">APK size (bytes)</label><input className="form-input" type="number" value={form.size_bytes} onChange={e => setForm({...form, size_bytes: Number(e.target.value)})} /></div></div>
        <div className="form-group"><label className="form-label">Download path *</label><input className="form-input" value={form.path} onChange={e => setForm({...form, path: e.target.value})} placeholder="/api/launcher-download/413/nonroot.apk" /></div>
        <div className="form-group"><label className="form-label">SHA-256 *</label><input className="form-input" style={{ fontFamily: 'var(--font-mono)' }} value={form.sha256} onChange={e => setForm({...form, sha256: e.target.value})} placeholder="64-character hex digest" /></div>
        <div className="form-group"><label className="form-label">Release notes</label><textarea className="form-textarea" value={form.notes} onChange={e => setForm({...form, notes: e.target.value})} /></div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}><input type="checkbox" checked={form.test_channel} onChange={e => setForm({...form, test_channel: e.target.checked})} /> Test channel release</label>
      </div><div className="modal-footer"><button className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button><button className="btn btn-primary" onClick={submit} disabled={saving}>{saving ? 'Publishing…' : 'Publish'}</button></div>
    </div></div>}
  </>
}

function defaultForm() { return { build: 1, flavor: 'nonroot', version: '', notes: '', path: '', sha256: '', size_bytes: 0, test_channel: false } }
function formatBytes(n: number) { if (!n) return '—'; const units = ['B', 'KB', 'MB', 'GB']; let i = 0; let x = n; while (x >= 1024 && i < units.length - 1) { x /= 1024; i++ } return `${x.toFixed(i ? 1 : 0)} ${units[i]}` }
