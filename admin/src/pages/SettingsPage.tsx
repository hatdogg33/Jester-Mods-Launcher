export function SettingsPage() {
  return (
    <div className="card">
      <div className="card-header"><span className="card-title">Settings</span></div>
      <div className="card-body">
        <div style={{ maxWidth: 600 }}>
          <h3 style={{ marginBottom: 16 }}>Admin Console Settings</h3>
          <div style={{ color: 'var(--text-muted)', marginBottom: 24 }}>
            The admin token is currently set in the Worker's environment variables.
            To change it, use <code>wrangler secret put ADMIN_API_TOKEN</code> or update the <code>ADMIN_API_TOKEN</code>
            var in <code>wrangler.toml</code> and redeploy.
          </div>
          <h3 style={{ marginTop: 32, marginBottom: 16 }}>API Endpoints</h3>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 2 }}>
            <code>GET  /api/_admin/health</code> — health check<br/>
            <code>GET  /api/_admin/stats</code> — system statistics<br/>
            <code>GET  /api/_admin/modules</code> — list catalog modules<br/>
            <code>POST /api/_admin/modules</code> — create module<br/>
            <code>PUT  /api/_admin/modules/:slug</code> — update module<br/>
            <code>DEL  /api/_admin/modules/:slug</code> — delete module<br/>
            <code>GET  /api/_admin/releases</code> — list launcher releases<br/>
            <code>POST /api/_admin/releases</code> — publish release<br/>
            <code>DEL  /api/_admin/releases/:build</code> — delete release<br/>
            <code>GET  /api/_admin/private-approvals</code> — list approvals<br/>
            <code>POST /api/_admin/private-approvals</code> — grant/revoke approval<br/>
          </div>
          <h3 style={{ marginTop: 32, marginBottom: 16 }}>Deployment</h3>
          <div style={{ color: 'var(--text-muted)', lineHeight: 1.8 }}>
            Admin dashboard: Deploy this Vite app to Cloudflare Pages (connect GitHub repo).<br/>
            Worker: <code>cd /root/jester-backend && npx wrangler deploy</code>
          </div>
        </div>
      </div>
    </div>
  )
}