import type { Page } from '../types'

interface Props { page: Page; onPageChange: (page: Page) => void; open: boolean; onToggle: (open: boolean) => void }

const items: Array<{ id: Page; label: string; icon: string }> = [
  { id: 'dashboard', label: 'Dashboard', icon: '▦' },
  { id: 'modules', label: 'Modules / Catalog', icon: '◈' },
  { id: 'releases', label: 'Launcher Releases', icon: '↟' },
  { id: 'private-approvals', label: 'Private Approvals', icon: '♢' },
]

export function Sidebar({ page, onPageChange, open, onToggle }: Props) {
  return (
    <aside className={`sidebar ${open ? 'open' : ''}`}>
      <div className="sidebar-header">
        <div className="sidebar-title"><span style={{ color: 'var(--accent)', fontSize: '1.4rem' }}>♠</span> Jester Mods</div>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>ADMIN CONSOLE</div>
      </div>
      <nav className="sidebar-nav">
        {items.map(item => (
          <button key={item.id} className={`nav-item ${page === item.id ? 'active' : ''}`} onClick={() => { onPageChange(item.id); onToggle(false) }}>
            <span className="nav-icon" style={{ fontSize: '1.1rem', lineHeight: 1 }}>{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>
      <div style={{ padding: '16px', borderTop: '1px solid var(--border)' }}>
        <button className={`nav-item ${page === 'settings' ? 'active' : ''}`} onClick={() => { onPageChange('settings'); onToggle(false) }}>
          <span className="nav-icon">⚙</span> Settings
        </button>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem', marginTop: '12px', paddingLeft: '12px' }}>
          Worker: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--success)' }}>● online</span>
        </div>
      </div>
    </aside>
  )
}