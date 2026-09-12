export type Page = 'dashboard' | 'modules' | 'releases' | 'private-approvals' | 'settings'

export interface Module {
  slug: string
  package_name: string
  title: string
  summary: string
  description: string
  developer: string
  versions: string[]
  version_codes: number[]
  abis: string[]
  build: number
  published_at: number
  updated_at: number
  tags: string[]
  featured: number
  category: string
  download_size_by_abi: Record<string, number>
  default_version: string
  icon_path: string | null
  icon_sha256: string | null
  icon_size: number | null
  entry_point: string
  install_json: string | null
  private_scope: string | null
  update_status: string
  popularity: number
  feature_count: number
}

export interface ModuleBuild {
  slug: string
  build: number
  package_name: string
  version: string
  dex_path: string
  dex_size: number
  dex_sha256: string
  native_path: string
  native_size: number
  native_sha256: string
  features_json: string
}

export interface ModuleChangelog {
  slug: string
  build: number
  version: string
  update_type: string
  notes: string
  published_at: number
}

export interface LauncherRelease {
  build: number
  flavor: string
  version: string
  notes: string
  path: string
  sha256: string
  size_bytes: number
  test_channel: number
  published_at: number
}

export interface PrivateApproval {
  scope: string
  installation_id: string
  device_id: string
  recovery_id: string
  flavor: string
  proof_key_id: string
  approved: number
  grant_issued_at: number
  grant_expires_at: number
}

export interface AdminStats {
  modules: number
  builds: number
  releases: number
  private_approvals: number
  active_keys: number
  unique_devices: number
}