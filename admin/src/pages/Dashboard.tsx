import { useEffect, useState } from 'react'
import type { AdminStats } from '../types'

interface Props {
  apiGet: <T>(path: string) => Promise<T>
  addToast: (message: string, type: 'success' | 'error' | 'info') => void
}

export function Dashboard({ apiGet, addToast }: Props) {
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      setStats(await apiGet<AdminStats & { ok: boolean }>('/api/_admin/stats'))
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Could not load statistics', 'error')
    } finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [])

  if (loading) return <div className="loading"><span className="spinner" />Loading dashboard…</div>

  const cards = [
    { label: 'Catalog modules', value: stats?.modules ?? 0, icon: '◈', color: 'var(--accent)' },
    { label: 'Published builds', value: stats?.builds ?? 0, icon: '▣', color: 'var(--success)' },
    { label: 'Launcher releases', value: stats?.releases ?? 0, icon: '↟', color: 'var(--warning)' },
    { label: 'Private approvals', value: stats?.private_approvals ?? 0, icon: '♢', color: '#bc8cff' },
    { label: 'Active access keys', value: stats?.active_keys ?? 0, icon: '⌁', color: 'var(--accent)' },
    { label: 'Unique devices', value: stats?.unique_devices ?? 0, icon: '◉', color: 'var(--success)' },
  ]

  return <>
    <div className="page-header">
      <div>
        <div style={{ color: 'var(--text-muted)', marginTop: 4 }}>Manage the launcher catalog, releases, and access.</div>
      </div>
      <button className="btn btn-secondary" onClick={() => void load()}>↻ Refresh</button>
    </div>
    <div className="stats-grid">
      {cards.map(card => <div className="stat-card" key={card.label}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div className="stat-label">{card.label}</div>
          <span style={{ color: card.color, fontSize: '1.3rem' }}>{card.icon}</span>
        </div>
        <div className="stat-value">{card.value}</div>
      </div>)}
    </div>
    <div className="card">
      <div className="card-header"><span className="card-title">System status</span><span className="badge badge-success">Operational</span></div>
      <div className="card-body">
        <div style={{ display: 'grid', gap: 14 }}>
          <StatusRow label="Cloudflare Worker" value="voidmod1.uncledrew697.workers.dev" status="Online" />
          <StatusRow label="D1 database" value="jester-db" status="Connected" />
          <StatusRow label="KV capabilities" value="MODULES_KV" status="Connected" />
          <StatusRow label="R2 payload storage" value="Pending enablement" status="Unavailable" warning />
        </div>
        <div style={{ marginTop: 20, padding: 14, borderRadius: 6, background: 'rgba(210,153,34,0.1)', border: '1px solid rgba(210,153,34,0.3)', color: 'var(--warning)', fontSize: '0.85rem' }}>
          Enable Cloudflare R2 to serve native libraries, DEX files, icons, and APK downloads.
        </div>
      </div>
    </div>
  </>
}

function StatusRow({ label, value, status, warning }: { label: string; value: string; status: string; warning?: boolean }) {
  return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
    <div><div style={{ fontWeight: 500 }}>{label}</div><code style={{ color: 'var(--text-muted)' }}>{value}</code></div>
    <span className={`badge ${warning ? 'badge-warning' : 'badge-success'}`}>{status}</span>
  </div>
}