import { useState } from 'react'
import { Sidebar } from './components/Sidebar'
import { ToastProvider, ToastContainer, useToast } from './components/Toast'
import { Dashboard } from './pages/Dashboard'
import { ModulesPage } from './pages/ModulesPage'
import { ReleasesPage } from './pages/ReleasesPage'
import { PrivateApprovalsPage } from './pages/PrivateApprovalsPage'
import { SettingsPage } from './pages/SettingsPage'
import type { Page } from './types'

const API_BASE = 'https://voidmod1.uncledrew697.workers.dev'
const ADMIN_TOKEN = 'admin-token-change-me-in-secrets'

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ADMIN_TOKEN}`,
      ...options.headers,
    },
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`)
  return data
}

function AppContent() {
  const [page, setPage] = useState<Page>('dashboard')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const { toasts, addToast, removeToast } = useToast()

  const apiGet = <T,>(path: string) => api<T>(path)
  const apiPost = <T,>(path: string, body: unknown) => api<T>(path, { method: 'POST', body: JSON.stringify(body) })
  const apiPut = <T,>(path: string, body: unknown) => api<T>(path, { method: 'PUT', body: JSON.stringify(body) })
  const apiDelete = <T,>(path: string) => api<T>(path, { method: 'DELETE' })

  return (
    <div className="app">
      <Sidebar
        page={page}
        onPageChange={setPage}
        open={sidebarOpen}
        onToggle={setSidebarOpen}
      />
      <div className={`sidebar-overlay ${sidebarOpen ? 'open' : ''}`} onClick={() => setSidebarOpen(false)} />
      <main className="main-content">
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '12px' }}>
          <button className="menu-toggle" onClick={() => setSidebarOpen(true)} aria-label="Open menu">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
          </button>
          <h1 className="page-title">{page.charAt(0).toUpperCase() + page.slice(1)}</h1>
        </header>
        <ToastContainer toasts={toasts} onRemove={removeToast} />
        {page === 'dashboard' && <Dashboard apiGet={apiGet} addToast={addToast} />}
        {page === 'modules' && <ModulesPage apiGet={apiGet} apiPost={apiPost} apiPut={apiPut} apiDelete={apiDelete} addToast={addToast} />}
        {page === 'releases' && <ReleasesPage apiGet={apiGet} apiPost={apiPost} apiDelete={apiDelete} addToast={addToast} />}
        {page === 'private-approvals' && <PrivateApprovalsPage apiGet={apiGet} apiPost={apiPost} addToast={addToast} />}
        {page === 'settings' && <SettingsPage />}
      </main>
    </div>
  )
}

export function App() {
  return <ToastProvider><AppContent /></ToastProvider>
}