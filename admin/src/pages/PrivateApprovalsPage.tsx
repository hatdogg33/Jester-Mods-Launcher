import { useEffect, useState } from 'react'
import type { PrivateApproval } from '../types'

interface Props {
  apiGet: <T>(path: string) => Promise<T>
  apiPost: <T>(path: string, body: unknown) => Promise<T>
  addToast: (message: string, type: 'success' | 'error' | 'info') => void
}

export function PrivateApprovalsPage({ apiGet, apiPost, addToast }: Props) {
  const [approvals, setApprovals] = useState<PrivateApproval[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [form, setForm] = useState<any>(defaultForm())
  const [saving, setSaving] = useState(false)

  const load = async () => {
    setLoading(true)
    try { setApprovals((await apiGet<{ approvals: PrivateApproval[] }>('/api/_admin/private-approvals')).approvals) }
    catch (e) { addToast(e instanceof Error ? e.message : 'Load failed', 'error') }
    finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [])

  const submit = async () => {
    setSaving(true)
    try { await apiPost('/api/_admin/private-approvals', form); addToast('Approval saved', 'success'); setShowModal(false); setForm(defaultForm()); await load() }
    catch (e) { addToast(e instanceof Error ? e.message : 'Save failed', 'error') }
    finally { setSaving(false) }
  }

  if (loading) return <div className="loading"><span className="spinner" />Loading approvals…</div>
  return <>
    <div className="page-header"><h1 className="page-title">Private Approvals</h1><button className="btn btn-primary" onClick={() => { setForm(defaultForm()); setShowModal(true) }}>+ Grant approval</button></div>
    <div className="card"><div className="card-body" style={{ padding: 0 }}><div className="table-wrapper"><table>
      <thead><tr><th>Scope</th><th>Device</th><th>Flavor</th><th>Proof key</th><th>Status</th><th>Grant expires</th></tr></thead>
      <tbody>{approvals.length === 0 ? <tr><td colSpan={6}><div className="empty-state"><div className="empty-icon">♢</div><div className="empty-title">No private approvals</div><div>Grant a private scope to a specific device.</div></div></td></tr> : approvals.map(a => <tr key={`${a.scope}-${a.device_id}`}>
        <td><code>{a.scope}</code></td><td><code>{a.device_id.slice(0, 16)}…</code></td><td><span className={`badge badge-${a.flavor === 'root' ? 'info' : 'success'}`}>{a.flavor}</span></td><td><code>{a.proof_key_id.slice(0, 16)}…</code></td><td><span className={`badge ${a.approved ? 'badge-success' : 'badge-danger'}`}>{a.approved ? 'Approved' : 'Revoked'}</span></td><td>{new Date(a.grant_expires_at * 1000).toLocaleString()}</td>
      </tr>)}</tbody>
    </table></div></div></div>
    {showModal && <div className="modal-overlay" onClick={() => { setShowModal(false); setForm(defaultForm()) }}><div className="modal" onClick={e => e.stopPropagation()}>
      <div className="modal-header"><h2 className="modal-title">Grant private approval</h2><button className="modal-close" onClick={() => { setShowModal(false); setForm(defaultForm()) }}>✕</button></div>
      <div className="modal-body">
        <div className="form-group"><label className="form-label">Scope *</label><input className="form-input" value={form.scope} onChange={e => setForm({...form, scope: e.target.value})} placeholder="beta.cheats" /></div>
        <div className="form-group"><label className="form-label">Device ID *</label><input className="form-input" value={form.device_id} onChange={e => setForm({...form, device_id: e.target.value})} placeholder="base64url device hash" /></div>
        <div className="form-group"><label className="form-label">Recovery ID *</label><input className="form-input" value={form.recovery_id} onChange={e => setForm({...form, recovery_id: e.target.value})} placeholder="base64url recovery hash" /></div>
        <div className="form-group"><label className="form-label">Flavor</label><select className="form-select" value={form.flavor} onChange={e => setForm({...form, flavor: e.target.value})}><option value="nonroot">Non-root</option><option value="root">Root</option></select></div>
        <div className="form-group"><label className="form-label">Proof key ID *</label><input className="form-input" value={form.proof_key_id} onChange={e => setForm({...form, proof_key_id: e.target.value})} placeholder="base64url proof key hash" /></div>
        <div className="form-row"><div className="form-group"><label className="form-label">Grant expires at (unix epoch)</label><input className="form-input" type="number" value={form.grant_expires_at} onChange={e => setForm({...form, grant_expires_at: Number(e.target.value)})} /></div></div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}><input type="checkbox" checked={form.approved} onChange={e => setForm({...form, approved: e.target.checked})} /> Approved</label>
      </div><div className="modal-footer"><button className="btn btn-secondary" onClick={() => { setShowModal(false); setForm(defaultForm()) }}>Cancel</button><button className="btn btn-primary" onClick={submit} disabled={saving}>{saving ? 'Saving…' : 'Grant'}</button></div>
    </div></div>}
  </>
}

function defaultForm() { return { scope: '', device_id: '', recovery_id: '', flavor: 'nonroot', proof_key_id: '', approved: true, grant_expires_at: Math.floor(Date.now() / 1000) + 315360000 } }