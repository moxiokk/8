<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'

type View = 'dashboard' | 'sites' | 'listeners' | 'connections' | 'http_connections' | 'certificates' | 'security' | 'logs' | 'settings'

interface AclCondition {
  field: 'ip' | 'uri' | 'host' | 'method' | 'user_agent' | 'referer' | 'header'
  operator: 'equal' | 'not_equal' | 'contains' | 'not_contains' | 'starts_with' | 'ends_with' | 'regex' | 'in_cidr' | 'not_in_cidr'
  value: string
  header_name: string
  case_sensitive: boolean
}

interface AclRule {
  name: string
  enabled: boolean
  conditions: AclCondition[]
  action: 'allow' | 'deny' | 'redirect' | 'return'
  status: 301 | 302 | 307 | 308 | 403 | 404 | 429
  redirect_location: string
}

interface RedirectRule {
  name: string
  enabled: boolean
  source_host: string
  source_path: string
  match: 'exact' | 'prefix'
  destination: string
  status: 301 | 302 | 307 | 308
  preserve_path: boolean
  preserve_query: boolean
}

interface UrlAuthUri {
  path: string
  match: 'exact' | 'prefix'
}

interface Status {
  uptime_seconds: number
  site_count: number
  active_revision: number
  stored_revision: number
  restart_required: boolean
  hot_reload_enabled: boolean
}

interface Site {
  id: number
  name: string
  enabled: boolean
  domains: string[]
  backend_address: string
  backend_port: number
  backend_protocol: 'http' | 'https'
  backend_host: string
  backend_tls_sni: string
  backend_tls_verify_certificate: boolean
  backend_connect_timeout_seconds: number
  backend_response_timeout_seconds: number
  backend_keep_alive: boolean
  http_enabled: boolean
  http_port: number
  https_enabled: boolean
  https_port: number
  force_https: boolean
  acl_rules: AclRule[]
  rate_limit_enabled: boolean
  rate_limit_window_seconds: number
  rate_limit_max_requests: number
  rate_limit_ban_seconds: number
  url_auth_enabled: boolean
  url_auth_scope: 'all' | 'specified'
  url_auth_primary_key: string
  url_auth_backup_key: string
  url_auth_validity_seconds: number
  url_auth_protected_uris: UrlAuthUri[]
  hotlink_enabled: boolean
  hotlink_extensions: string[]
  hotlink_allowed_hosts: string[]
  hotlink_allow_empty_referer: boolean
  hotlink_redirect_location: string
  redirect_rules: RedirectRule[]
  backend_max_active_connections: number
  backend_max_queue: number
  backend_queue_timeout_seconds: number
}

interface SiteDraft extends Omit<Site, 'id' | 'domains' | 'hotlink_extensions' | 'hotlink_allowed_hosts'> {
  id?: number
  domains_text: string
  hotlink_extensions_text: string
  hotlink_allowed_hosts_text: string
}

interface Certificate {
  id: number
  name: string
  enabled: boolean
  is_default: boolean
  domains: string[]
  certificate_pem: string
  has_private_key: boolean
}

interface CertificateDraft {
  id?: number
  name: string
  enabled: boolean
  is_default: boolean
  domains_text: string
  certificate_pem: string
  private_key_pem: string
}

interface RuntimeSettings {
  trusted_proxy_cidrs: string[]
  real_ip_headers: string[]
  max_upload_bytes: number
  backend_keep_alive: boolean
  backend_pool_size: number
  client_header_timeout_seconds: number
  client_body_timeout_seconds: number
  client_write_timeout_seconds: number
  backend_connect_timeout_seconds: number
  backend_response_timeout_seconds: number
  backend_idle_timeout_seconds: number
  backend_idle_connection_ttl_seconds: number
}

interface AccessLogEntry { timestamp: string; request_id: string; client_ip: string; host: string; method: string; path: string; status: number; response_bytes: number; duration_ms: number }
interface ErrorLogEntry { timestamp: string; level: string; component: string; message: string; request_id?: string }
interface ListenerStatus { protocol: 'HTTP' | 'HTTPS'; address: string; configured_port: number; bound_port: number; site_count: number; status: string }
interface ConnectionInfo { id: number; protocol: 'HTTP' | 'HTTPS'; source_address: string; connected_at_unix_ms: number; connected_seconds: number; status: string; method: string; url: string; referer: string }
interface HttpConnectionInfo { id: number; site_id: number; site_name: string; host: string; protocol: 'HTTP' | 'HTTPS'; client_ip: string; connected_at_unix_ms: number; connected_seconds: number; status: string; method: string; url: string; referer: string }
interface BackendMetric { site_id: number; site_name: string; backend: string; maximum_active: number; maximum_queue: number; queue_timeout_seconds: number; active_connections: number; queue_length: number; rejected_requests: number; queue_timeouts: number }
interface BackendTestResult { success: boolean; protocol: string; remote_address: string; remote_port: number; latency_ms: number; tls_verified: boolean; error: string }

const loading = ref(true)
const setupMode = ref(false)
const authenticated = ref(false)
const activeView = ref<View>('dashboard')
const status = ref<Status | null>(null)
const sites = ref<Site[]>([])
const certificates = ref<Certificate[]>([])
const settings = ref<RuntimeSettings | null>(null)
const listeners = ref<ListenerStatus[]>([])
const connections = ref<ConnectionInfo[]>([])
const connectionTotal = ref(0)
const connectionsLoading = ref(false)
const httpConnections = ref<HttpConnectionInfo[]>([])
const httpConnectionTotal = ref(0)
const httpConnectionsLoading = ref(false)
const httpConnectionSiteId = ref<number | ''>('')
const backendMetrics = ref<BackendMetric[]>([])
const errorMessage = ref('')
const notice = ref('')
const modalOpen = ref(false)
const saving = ref(false)
const backendTesting = ref(false)
const backendTestResult = ref<BackendTestResult | null>(null)
const certificateModalOpen = ref(false)
const settingsSaving = ref(false)
const backupBusy = ref(false)
const restoreInput = ref<HTMLInputElement | null>(null)
const logsLoading = ref(false)
const logTab = ref<'access' | 'error'>('access')
const logLimit = ref<100 | 500 | 1000>(100)
const accessLogs = ref<AccessLogEntry[]>([])
const errorLogs = ref<ErrorLogEntry[]>([])
const accessFilters = reactive({ host: '', ip: '', status: '', request_id: '', path: '' })
const errorFilters = reactive({ level: '', request_id: '', search: '' })
const credentials = reactive({ username: '', password: '' })
const draft = reactive<SiteDraft>(emptyDraft())
const certificateDraft = reactive<CertificateDraft>(emptyCertificateDraft())
const settingsDraft = reactive({
  trusted_proxy_cidrs_text: '', real_ip_headers: [] as string[], new_real_ip_header: '', max_upload_mb: 64,
  backend_keep_alive: true, backend_pool_size: 32,
  client_header_timeout_seconds: 15, client_body_timeout_seconds: 120,
  client_write_timeout_seconds: 60, backend_connect_timeout_seconds: 5,
  backend_response_timeout_seconds: 60, backend_idle_timeout_seconds: 60,
  backend_idle_connection_ttl_seconds: 60,
})

const navigation = [
  { id: 'dashboard', label: '首页', glyph: '◫', ready: true },
  { id: 'sites', label: '网站管理', glyph: '◎', ready: true },
  { id: 'listeners', label: '监听端口', glyph: '⌁', ready: true },
  { id: 'connections', label: 'TCP 连接', glyph: '↔', ready: true },
  { id: 'http_connections', label: 'HTTP 实时', glyph: '⇄', ready: true },
  { id: 'certificates', label: 'SSL 证书', glyph: '◇', ready: true },
  { id: 'security', label: '访问策略', glyph: '⊘', ready: true },
  { id: 'logs', label: '日志', glyph: '≡', ready: true },
  { id: 'settings', label: '系统设置', glyph: '⚙', ready: true },
]

const pageTitle = computed(() => ({ dashboard: '运行概览', sites: '网站管理', listeners: '监听端口', connections: 'TCP 连接信息', http_connections: 'HTTP 实时连接', certificates: 'SSL 证书', security: '访问策略', logs: '日志', settings: '系统设置' })[activeView.value])
let connectionRefreshTimer: number | undefined

function emptyCertificateDraft(): CertificateDraft {
  return { name: '', enabled: true, is_default: false, domains_text: '', certificate_pem: '', private_key_pem: '' }
}

function emptyDraft(): SiteDraft {
  return {
    name: '',
    enabled: true,
    domains_text: '',
    backend_address: '127.0.0.1',
    backend_port: 8090,
    backend_protocol: 'http',
    backend_host: '',
    backend_tls_sni: '',
    backend_tls_verify_certificate: true,
    backend_connect_timeout_seconds: 5,
    backend_response_timeout_seconds: 60,
    backend_keep_alive: true,
    http_enabled: true,
    http_port: 80,
    https_enabled: false,
    https_port: 443,
    force_https: false,
    acl_rules: [],
    rate_limit_enabled: false,
    rate_limit_window_seconds: 10,
    rate_limit_max_requests: 100,
    rate_limit_ban_seconds: 60,
    url_auth_enabled: false,
    url_auth_scope: 'all',
    url_auth_primary_key: '',
    url_auth_backup_key: '',
    url_auth_validity_seconds: 1800,
    url_auth_protected_uris: [],
    hotlink_enabled: false,
    hotlink_extensions_text: 'jpg, jpeg, png, gif, webp, mp4, zip',
    hotlink_allowed_hosts_text: '',
    hotlink_allow_empty_referer: true,
    hotlink_redirect_location: '',
    redirect_rules: [],
    backend_max_active_connections: 200,
    backend_max_queue: 1000,
    backend_queue_timeout_seconds: 5,
  }
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body) headers.set('Content-Type', 'application/json')
  if (options.method && options.method !== 'GET') headers.set('X-WebServer-Admin', '1')
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin' })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    if (response.status === 401) authenticated.value = false
    throw new Error(payload.error || `请求失败 (${response.status})`)
  }
  return payload as T
}

async function bootstrap() {
  loading.value = true
  try {
    const setup = await api<{ setup_required: boolean }>('/api/auth/setup-state')
    setupMode.value = setup.setup_required
    if (!setupMode.value) {
      try {
        await loadData()
        authenticated.value = true
      } catch {
        authenticated.value = false
      }
    }
  } catch (error) {
    errorMessage.value = messageOf(error)
  } finally {
    loading.value = false
  }
}

async function submitCredentials() {
  errorMessage.value = ''
  try {
    await api(setupMode.value ? '/api/auth/setup' : '/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    })
    setupMode.value = false
    authenticated.value = true
    credentials.password = ''
    await loadData()
  } catch (error) {
    errorMessage.value = messageOf(error)
  }
}

async function loadData() {
  const [nextStatus, sitePayload, certificatePayload, nextSettings, listenerPayload, metricPayload] = await Promise.all([
    api<Status>('/api/status'),
    api<{ sites: Site[] }>('/api/sites'),
    api<{ certificates: Certificate[] }>('/api/certificates'),
    api<RuntimeSettings>('/api/settings'),
    api<{ listeners: ListenerStatus[] }>('/api/listeners'),
    api<{ backends: BackendMetric[] }>('/api/backends/metrics'),
  ])
  status.value = nextStatus
  sites.value = sitePayload.sites
  certificates.value = certificatePayload.certificates
  settings.value = nextSettings
  listeners.value = listenerPayload.listeners
  backendMetrics.value = metricPayload.backends
  Object.assign(settingsDraft, {
    trusted_proxy_cidrs_text: nextSettings.trusted_proxy_cidrs.join('\n'),
    real_ip_headers: [...nextSettings.real_ip_headers],
    max_upload_mb: Math.max(1, Math.round(nextSettings.max_upload_bytes / 1024 / 1024)),
    backend_keep_alive: nextSettings.backend_keep_alive,
    backend_pool_size: nextSettings.backend_pool_size,
    client_header_timeout_seconds: nextSettings.client_header_timeout_seconds,
    client_body_timeout_seconds: nextSettings.client_body_timeout_seconds,
    client_write_timeout_seconds: nextSettings.client_write_timeout_seconds,
    backend_connect_timeout_seconds: nextSettings.backend_connect_timeout_seconds,
    backend_response_timeout_seconds: nextSettings.backend_response_timeout_seconds,
    backend_idle_timeout_seconds: nextSettings.backend_idle_timeout_seconds,
    backend_idle_connection_ttl_seconds: nextSettings.backend_idle_connection_ttl_seconds,
  })
}

async function logout() {
  try { await api('/api/auth/logout', { method: 'POST' }) } catch { /* session may already be gone */ }
  authenticated.value = false
  credentials.password = ''
}

async function reloadRuntime() {
  errorMessage.value = ''
  try {
    const result = await api<{ active_revision: number }>('/api/runtime/reload', { method: 'POST' })
    notice.value = `运行态已重新加载到 r${result.active_revision}；新连接将使用最新证书。`
    await loadData()
  } catch (error) {
    errorMessage.value = messageOf(error)
  }
}

function selectView(id: string, ready: boolean) {
  if (!ready) {
    notice.value = '该模块将在后续阶段启用。'
    window.setTimeout(() => { notice.value = '' }, 2200)
    return
  }
  activeView.value = id as View
  if (id === 'logs') void loadLogs()
  if (id === 'listeners') void loadData()
  if (id === 'connections') void loadConnections()
  if (id === 'http_connections') void loadHttpConnections()
}

async function loadConnections(showLoading = true) {
  if (showLoading) connectionsLoading.value = true
  try {
    const payload = await api<{ connections: ConnectionInfo[]; total: number }>('/api/connections')
    connections.value = payload.connections
    connectionTotal.value = payload.total
  } catch (error) {
    errorMessage.value = messageOf(error)
  } finally {
    if (showLoading) connectionsLoading.value = false
  }
}

async function loadHttpConnections(showLoading = true) {
  if (showLoading) httpConnectionsLoading.value = true
  try {
    const query = httpConnectionSiteId.value === '' ? '' : `?site_id=${httpConnectionSiteId.value}`
    const payload = await api<{ connections: HttpConnectionInfo[]; total: number }>(`/api/http-connections${query}`)
    httpConnections.value = payload.connections
    httpConnectionTotal.value = payload.total
  } catch (error) {
    errorMessage.value = messageOf(error)
  } finally {
    if (showLoading) httpConnectionsLoading.value = false
  }
}

async function exportConfiguration() {
  backupBusy.value = true
  errorMessage.value = ''
  try {
    const response = await fetch('/api/config/backup', {
      credentials: 'same-origin',
      headers: { 'X-WebServer-Admin': '1' },
    })
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}))
      throw new Error(payload.error || `导出失败 (${response.status})`)
    }
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `webserver-config-${new Date().toISOString().slice(0, 10)}.json`
    link.click()
    URL.revokeObjectURL(url)
    notice.value = '配置备份已导出。文件包含 TLS 私钥，请安全保管。'
  } catch (error) { errorMessage.value = messageOf(error) }
  finally { backupBusy.value = false }
}

async function importConfiguration(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  if (!window.confirm('导入会原子替换全部网站、证书和系统设置，但保留管理员账号。继续吗？')) return
  backupBusy.value = true
  errorMessage.value = ''
  try {
    const encoded = await file.text()
    await api<{ active_revision: number }>('/api/config/restore', { method: 'POST', body: encoded })
    notice.value = '配置已完整校验、恢复并热更新；管理员账号保持不变。'
    await loadData()
  } catch (error) { errorMessage.value = messageOf(error) }
  finally { backupBusy.value = false }
}

function moveRealIpHeader(index: number, direction: -1 | 1) {
  const target = index + direction
  if (target < 0 || target >= settingsDraft.real_ip_headers.length) return
  const [header] = settingsDraft.real_ip_headers.splice(index, 1)
  settingsDraft.real_ip_headers.splice(target, 0, header)
}

function addRealIpHeader() {
  const header = settingsDraft.new_real_ip_header.trim()
  if (!header || settingsDraft.real_ip_headers.some(value => value.toLowerCase() === header.toLowerCase())) return
  settingsDraft.real_ip_headers.push(header)
  settingsDraft.new_real_ip_header = ''
}

async function loadLogs() {
  logsLoading.value = true
  errorMessage.value = ''
  try {
    const parameters = new URLSearchParams({ limit: String(logLimit.value) })
    const filters = logTab.value === 'access' ? accessFilters : errorFilters
    for (const [key, value] of Object.entries(filters)) if (value) parameters.set(key, value)
    if (logTab.value === 'access') {
      accessLogs.value = (await api<{ entries: AccessLogEntry[] }>(`/api/logs/access?${parameters}`)).entries
    } else {
      errorLogs.value = (await api<{ entries: ErrorLogEntry[] }>(`/api/logs/error?${parameters}`)).entries
    }
  } catch (error) { errorMessage.value = messageOf(error) }
  finally { logsLoading.value = false }
}

function selectLogTab(tab: 'access' | 'error') {
  logTab.value = tab
  void loadLogs()
}

function formatLogTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatConnectionTime(value: number) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString()
}

function formatConnectionDuration(seconds: number) {
  if (seconds < 60) return `${seconds} 秒`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`
  return `${Math.floor(seconds / 3600)} 小时 ${Math.floor((seconds % 3600) / 60)} 分`
}

function openCreate() {
  Object.assign(draft, emptyDraft())
  delete draft.id
  backendTestResult.value = null
  modalOpen.value = true
}

function openEdit(site: Site) {
  Object.assign(draft, {
    ...site,
    domains_text: site.domains.join('\n'),
    hotlink_extensions_text: site.hotlink_extensions.join(', '),
    hotlink_allowed_hosts_text: site.hotlink_allowed_hosts.join('\n'),
    acl_rules: site.acl_rules.map(rule => ({ ...rule, conditions: rule.conditions.map(condition => ({ ...condition })) })),
    redirect_rules: site.redirect_rules.map(rule => ({ ...rule })),
    url_auth_protected_uris: site.url_auth_protected_uris.map(rule => ({ ...rule })),
  })
  backendTestResult.value = null
  modalOpen.value = true
}

function setBackendHostMode(event: Event) {
  const mode = (event.target as HTMLSelectElement).value
  draft.backend_host = mode === 'custom' ? draft.backend_address : ''
}

function changeBackendProtocol() {
  draft.backend_port = draft.backend_protocol === 'https' ? 443 : 80
  if (draft.backend_protocol === 'http') draft.backend_tls_sni = ''
  backendTestResult.value = null
}

async function testBackend() {
  backendTesting.value = true
  backendTestResult.value = null
  errorMessage.value = ''
  try {
    backendTestResult.value = await api<BackendTestResult>('/api/backends/test', {
      method: 'POST',
      body: JSON.stringify({
        backend_protocol: draft.backend_protocol,
        backend_address: draft.backend_address,
        backend_port: draft.backend_port,
        backend_host: draft.backend_host,
        backend_tls_sni: draft.backend_tls_sni,
        backend_tls_verify_certificate: draft.backend_tls_verify_certificate,
        backend_connect_timeout_seconds: draft.backend_connect_timeout_seconds,
      }),
    })
  } catch (error) { errorMessage.value = messageOf(error) }
  finally { backendTesting.value = false }
}

function addAclRule() {
  draft.acl_rules.push({
    name: '新 ACL 规则', enabled: true,
    conditions: [{ field: 'uri', operator: 'contains', value: '/.git', header_name: '', case_sensitive: false }],
    action: 'deny', status: 403, redirect_location: '',
  })
}

function addAclCondition(rule: AclRule) {
  rule.conditions.push({ field: 'uri', operator: 'contains', value: '', header_name: '', case_sensitive: false })
}

function isCidrOperator(operator: AclCondition['operator']) {
  return operator === 'in_cidr' || operator === 'not_in_cidr'
}

function normalizeAclCondition(condition: AclCondition) {
  if (condition.field !== 'ip' && isCidrOperator(condition.operator)) condition.operator = 'contains'
  if (isCidrOperator(condition.operator)) condition.case_sensitive = false
}

function normalizeAclAction(rule: AclRule) {
  if (rule.action === 'redirect' && ![301, 302, 307, 308].includes(rule.status)) rule.status = 302
  if ((rule.action === 'deny' || rule.action === 'return') && ![403, 404, 429].includes(rule.status)) rule.status = 403
}

function addRedirectRule() {
  draft.redirect_rules.push({
    name: '新重定向', enabled: true, source_host: '', source_path: '/', match: 'exact',
    destination: '/new', status: 301, preserve_path: false, preserve_query: true,
  })
}

function addUrlAuthUri() {
  draft.url_auth_protected_uris.push({ path: '/video/', match: 'prefix' })
}

async function saveSite() {
  saving.value = true
  errorMessage.value = ''
  const payload = {
    ...draft,
    domains: draft.domains_text.split(/[\n,]/).map(value => value.trim()).filter(Boolean),
    hotlink_extensions: draft.hotlink_extensions_text.split(/[\s,]+/).map(value => value.trim()).filter(Boolean),
    hotlink_allowed_hosts: draft.hotlink_allowed_hosts_text.split(/[\n,]/).map(value => value.trim()).filter(Boolean),
  }
  delete (payload as Partial<SiteDraft>).domains_text
  delete (payload as Partial<SiteDraft>).hotlink_extensions_text
  delete (payload as Partial<SiteDraft>).hotlink_allowed_hosts_text
  try {
    await api(draft.id ? `/api/sites/${draft.id}` : '/api/sites', {
      method: draft.id ? 'PUT' : 'POST',
      body: JSON.stringify(payload),
    })
    modalOpen.value = false
    notice.value = '配置已保存并热更新；新请求已使用最新运行态。'
    await loadData()
  } catch (error) {
    errorMessage.value = messageOf(error)
  } finally {
    saving.value = false
  }
}

async function removeSite(site: Site) {
  if (!window.confirm(`删除“${site.name}”？此操作不可撤销。`)) return
  try {
    await api(`/api/sites/${site.id}`, { method: 'DELETE' })
    notice.value = '网站已删除并热更新；对应 Listener 已按需回收。'
    await loadData()
  } catch (error) {
    errorMessage.value = messageOf(error)
  }
}

function openCreateCertificate() {
  Object.assign(certificateDraft, emptyCertificateDraft())
  certificateDraft.is_default = certificates.value.length === 0
  delete certificateDraft.id
  certificateModalOpen.value = true
}

function openEditCertificate(certificate: Certificate) {
  Object.assign(certificateDraft, {
    ...certificate,
    domains_text: certificate.domains.join('\n'),
    private_key_pem: '',
  })
  certificateModalOpen.value = true
}

async function readPemFile(event: Event, field: 'certificate_pem' | 'private_key_pem') {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) certificateDraft[field] = await file.text()
}

async function saveCertificate() {
  saving.value = true
  errorMessage.value = ''
  try {
    const payload = {
      name: certificateDraft.name,
      enabled: certificateDraft.enabled,
      is_default: certificateDraft.is_default,
      domains: certificateDraft.domains_text.split(/[\n,]/).map(value => value.trim()).filter(Boolean),
      certificate_pem: certificateDraft.certificate_pem,
      private_key_pem: certificateDraft.private_key_pem,
    }
    await api(certificateDraft.id ? `/api/certificates/${certificateDraft.id}` : '/api/certificates', {
      method: certificateDraft.id ? 'PUT' : 'POST', body: JSON.stringify(payload),
    })
    certificateModalOpen.value = false
    notice.value = '证书已校验并热更新；新 TLS 连接将立即使用新的 SNI 映射。'
    await loadData()
  } catch (error) {
    errorMessage.value = messageOf(error)
  } finally { saving.value = false }
}

async function removeCertificate(certificate: Certificate) {
  if (!window.confirm(`删除证书“${certificate.name}”？仍被 HTTPS 网站使用时，服务器会拒绝删除。`)) return
  try {
    await api(`/api/certificates/${certificate.id}`, { method: 'DELETE' })
    notice.value = '证书已删除，SNI 映射已热更新。'
    await loadData()
  } catch (error) { errorMessage.value = messageOf(error) }
}

async function saveSettings() {
  settingsSaving.value = true
  errorMessage.value = ''
  try {
    await api('/api/settings', {
      method: 'PUT',
      body: JSON.stringify({
        trusted_proxy_cidrs: settingsDraft.trusted_proxy_cidrs_text.split(/[\n,]/).map(value => value.trim()).filter(Boolean),
        real_ip_headers: settingsDraft.real_ip_headers,
        max_upload_bytes: Math.round(settingsDraft.max_upload_mb * 1024 * 1024),
        backend_keep_alive: settingsDraft.backend_keep_alive,
        backend_pool_size: settingsDraft.backend_pool_size,
        client_header_timeout_seconds: settingsDraft.client_header_timeout_seconds,
        client_body_timeout_seconds: settingsDraft.client_body_timeout_seconds,
        client_write_timeout_seconds: settingsDraft.client_write_timeout_seconds,
        backend_connect_timeout_seconds: settingsDraft.backend_connect_timeout_seconds,
        backend_response_timeout_seconds: settingsDraft.backend_response_timeout_seconds,
        backend_idle_timeout_seconds: settingsDraft.backend_idle_timeout_seconds,
        backend_idle_connection_ttl_seconds: settingsDraft.backend_idle_connection_ttl_seconds,
      }),
    })
    notice.value = '代理设置已热更新；只信任来自所列 CIDR 的真实 IP 请求头。'
    await loadData()
  } catch (error) { errorMessage.value = messageOf(error) }
  finally { settingsSaving.value = false }
}

function formatUptime(seconds = 0) {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return days ? `${days} 天 ${hours} 小时` : `${hours} 小时 ${minutes} 分钟`
}

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : '发生未知错误'
}

onMounted(() => {
  void bootstrap()
  connectionRefreshTimer = window.setInterval(() => {
    if (authenticated.value && activeView.value === 'connections') {
      void loadConnections(false)
    }
    if (authenticated.value && activeView.value === 'http_connections') {
      void loadHttpConnections(false)
    }
  }, 2000)
})
onUnmounted(() => {
  if (connectionRefreshTimer !== undefined) window.clearInterval(connectionRefreshTimer)
})
</script>

<template>
  <div v-if="loading" class="splash"><span class="pulse-mark">W</span><p>正在连接本地控制平面…</p></div>

  <main v-else-if="!authenticated" class="auth-shell">
    <section class="auth-card">
      <div class="brand-lockup"><span class="brand-mark">W</span><span>WebServer</span></div>
      <p class="eyebrow">LOCAL CONTROL PLANE</p>
      <h1>{{ setupMode ? '创建管理员' : '欢迎回来' }}</h1>
      <p class="auth-copy">{{ setupMode ? '首次运行需要创建本机管理员账户。密码至少 12 个字符。' : '登录以管理源站和反向代理配置。' }}</p>
      <form @submit.prevent="submitCredentials">
        <label>用户名<input v-model.trim="credentials.username" autocomplete="username" required minlength="3" /></label>
        <label>密码<input v-model="credentials.password" type="password" :autocomplete="setupMode ? 'new-password' : 'current-password'" required minlength="12" /></label>
        <p v-if="errorMessage" class="form-error">{{ errorMessage }}</p>
        <button class="primary wide" type="submit">{{ setupMode ? '创建并进入控制台' : '登录控制台' }}</button>
      </form>
      <p class="loopback-note"><span></span>仅允许 127.0.0.1 访问</p>
    </section>
  </main>

  <div v-else class="app-shell">
    <aside class="sidebar">
      <div class="brand-lockup"><span class="brand-mark">W</span><span>WebServer</span></div>
      <nav>
        <button v-for="item in navigation" :key="item.id" :class="{ active: activeView === item.id, muted: !item.ready }" @click="selectView(item.id, item.ready)">
          <span class="nav-glyph">{{ item.glyph }}</span><span>{{ item.label }}</span><small v-if="!item.ready">稍后</small>
        </button>
      </nav>
      <div class="sidebar-footer"><span class="status-dot"></span><div><strong>服务运行中</strong><small>v1.0.0 · TLS &amp; Streaming</small></div></div>
    </aside>

    <section class="workspace">
      <header class="topbar"><div><p class="eyebrow">ORIGIN SERVER</p><h1>{{ pageTitle }}</h1></div><div class="top-actions"><button class="ghost" @click="reloadRuntime">重新加载</button><button class="ghost" @click="loadData">刷新</button><button class="ghost" @click="logout">退出</button></div></header>
      <div v-if="notice" class="notice">{{ notice }}</div>
      <div v-if="errorMessage" class="error-banner">{{ errorMessage }}<button @click="errorMessage = ''">×</button></div>

      <template v-if="activeView === 'dashboard'">
        <div v-if="status?.restart_required" class="restart-banner"><span>热更新失败</span><p>SQLite 中有较新配置，但运行态保留上一个有效快照。修正配置后点击“重新加载”。</p></div>
        <div class="metric-grid">
          <article><p>运行时间</p><strong>{{ formatUptime(status?.uptime_seconds) }}</strong><span>Admin Plane</span></article>
          <article><p>网站数量</p><strong>{{ status?.site_count ?? 0 }}</strong><span>{{ sites.filter(site => site.enabled).length }} 个已启用</span></article>
          <article><p>活动配置</p><strong>r{{ status?.active_revision ?? 0 }}</strong><span>{{ status?.hot_reload_enabled ? 'Atomic Snapshot' : '未启用热更新' }}</span></article>
          <article><p>存储配置</p><strong>r{{ status?.stored_revision ?? 0 }}</strong><span>SQLite · WAL</span></article>
        </div>
        <section class="panel"><div class="panel-heading"><div><p class="eyebrow">SERVICE MAP</p><h2>网站运行状态</h2></div><button class="primary" @click="activeView = 'sites'">管理网站</button></div>
          <div class="site-summary" v-for="site in sites.slice(0, 5)" :key="site.id"><span :class="['site-state', { off: !site.enabled }]"></span><div><strong>{{ site.name }}</strong><small>{{ site.domains.join(' · ') }}</small></div><code>{{ site.backend_protocol }}://{{ site.backend_address }}:{{ site.backend_port }}</code><span class="badge">{{ site.enabled ? 'Running' : 'Disabled' }}</span></div>
          <div v-if="!sites.length" class="empty-state">还没有网站配置。</div>
        </section>
      </template>

      <template v-else-if="activeView === 'sites'">
        <div class="page-actions"><div><p>{{ sites.length }} 个网站 · 配置保存在 SQLite</p></div><button class="primary" @click="openCreate">＋ 添加网站</button></div>
        <section class="panel site-table"><div class="table-head"><span>网站</span><span>监听</span><span>后端</span><span>状态</span><span></span></div>
          <div class="table-row" v-for="site in sites" :key="site.id"><div><strong>{{ site.name }}</strong><small>{{ site.domains.join(' · ') }}</small></div><div class="listener-tags"><span v-if="site.http_enabled">HTTP :{{ site.http_port }}</span><span v-if="site.https_enabled">HTTPS :{{ site.https_port }}</span></div><code>{{ site.backend_protocol }}://{{ site.backend_address }}:{{ site.backend_port }}</code><span :class="['badge', { disabled: !site.enabled }]">{{ site.enabled ? 'Running' : 'Disabled' }}</span><div class="row-actions"><button @click="openEdit(site)">编辑</button><button class="danger" @click="removeSite(site)">删除</button></div></div>
          <div v-if="!sites.length" class="empty-state">没有网站。点击“添加网站”开始。</div>
        </section>
      </template>

      <template v-else-if="activeView === 'listeners'">
        <div class="page-actions"><div><p>端口由已启用的网站自动创建与回收，此页面显示实际运行状态</p></div><button class="ghost" @click="loadData">刷新状态</button></div>
        <section class="panel"><div class="table-head listener-head"><span>协议</span><span>地址</span><span>端口</span><span>网站</span><span>状态</span></div>
          <div class="table-row listener-row" v-for="listener in listeners" :key="listener.protocol + listener.bound_port"><strong>{{ listener.protocol }}</strong><code>{{ listener.address }}</code><strong>{{ listener.bound_port }}</strong><span>{{ listener.site_count }}</span><span class="badge">{{ listener.status }}</span></div>
          <div v-if="!listeners.length" class="empty-state">当前没有活动 Listener。</div>
        </section>
        <div class="page-actions backend-heading"><div><p>BACKEND OVERLOAD PROTECTION</p><h2>Backend 并发与队列</h2></div></div>
        <section class="panel backend-metrics"><div class="table-head backend-head"><span>网站 / Backend</span><span>Active</span><span>Queue</span><span>Rejected</span><span>限制</span></div>
          <div class="table-row backend-row" v-for="metric in backendMetrics" :key="metric.site_id"><div><strong>{{ metric.site_name }}</strong><small>{{ metric.backend }}</small></div><strong>{{ metric.active_connections }}</strong><strong>{{ metric.queue_length }}</strong><strong :class="{ 'danger-number': metric.rejected_requests > 0 }">{{ metric.rejected_requests }}</strong><div><small>Active {{ metric.maximum_active }} · Queue {{ metric.maximum_queue }}</small><small>等待 {{ metric.queue_timeout_seconds }}s · 超时 {{ metric.queue_timeouts }}</small></div></div>
          <div v-if="!backendMetrics.length" class="empty-state">没有可监控的网站 Backend。</div>
        </section>
      </template>

      <template v-else-if="activeView === 'connections'">
        <div class="page-actions"><div><p>{{ connectionTotal }} 条活动 TCP/TLS 连接<span v-if="connectionTotal > connections.length"> · 当前显示前 {{ connections.length }} 条</span> · 每 2 秒自动刷新</p></div><button class="ghost" :disabled="connectionsLoading" @click="loadConnections()">{{ connectionsLoading ? '刷新中…' : '立即刷新' }}</button></div>
        <section class="panel connections-panel"><div class="table-head connection-head"><span>源地址</span><span>连接时间</span><span>状态</span><span>Method / URL</span><span>Referer</span></div>
          <div class="table-row connection-row" v-for="connection in connections" :key="connection.id"><div><strong>{{ connection.source_address }}</strong><small>{{ connection.protocol }} · #{{ connection.id }}</small></div><div><span>{{ formatConnectionTime(connection.connected_at_unix_ms) }}</span><small>已连接 {{ formatConnectionDuration(connection.connected_seconds) }}</small></div><span class="badge">{{ connection.status }}</span><div><strong>{{ connection.method || '—' }}</strong><code :title="connection.url">{{ connection.url || '等待请求' }}</code></div><code :title="connection.referer">{{ connection.referer || '—' }}</code></div>
          <div v-if="!connections.length" class="empty-state">当前没有活动数据连接。</div>
        </section>
      </template>

      <template v-else-if="activeView === 'http_connections'">
        <div class="page-actions http-connection-actions"><div><p>{{ httpConnectionTotal }} 条活动 HTTP 请求<span v-if="httpConnectionTotal > httpConnections.length"> · 当前显示前 {{ httpConnections.length }} 条</span> · 每 2 秒自动刷新</p></div><div class="connection-filters"><select v-model="httpConnectionSiteId" @change="loadHttpConnections()"><option value="">所有网站</option><option v-for="site in sites" :key="site.id" :value="site.id">{{ site.name }} · {{ site.domains.join(' / ') }}</option></select><button class="ghost" :disabled="httpConnectionsLoading" @click="loadHttpConnections()">{{ httpConnectionsLoading ? '刷新中…' : '立即刷新' }}</button></div></div>
        <section class="panel connections-panel"><div class="table-head http-connection-head"><span>网站 / 用户 IP</span><span>连接时间 / 持续</span><span>状态</span><span>Method / URL</span><span>Referer</span></div>
          <div class="table-row http-connection-row" v-for="connection in httpConnections" :key="connection.id"><div><strong>{{ connection.site_name || '未匹配网站' }}</strong><small>{{ connection.client_ip }} · {{ connection.protocol }} · {{ connection.host || '—' }}</small></div><div><span>{{ formatConnectionTime(connection.connected_at_unix_ms) }}</span><small>已持续 {{ formatConnectionDuration(connection.connected_seconds) }}</small></div><span class="badge">{{ connection.status }}</span><div><strong>{{ connection.method || '—' }}</strong><code :title="connection.url">{{ connection.url || '—' }}</code></div><code :title="connection.referer">{{ connection.referer || '—' }}</code></div>
          <div v-if="!httpConnections.length" class="empty-state">当前筛选范围内没有活动 HTTP 请求。</div>
        </section>
      </template>

      <template v-else-if="activeView === 'certificates'">
        <div class="page-actions"><div><p>{{ certificates.length }} 张证书 · PEM/CRT + KEY · SNI 热更新</p></div><button class="primary" @click="openCreateCertificate">＋ 添加证书</button></div>
        <section class="panel site-table"><div class="table-head certificate-head"><span>证书</span><span>绑定域名</span><span>SNI</span><span>状态</span><span></span></div>
          <div class="table-row certificate-row" v-for="certificate in certificates" :key="certificate.id"><div><strong>{{ certificate.name }}</strong><small>{{ certificate.has_private_key ? '私钥已保存（API 不回显）' : '缺少私钥' }}</small></div><div><small>{{ certificate.domains.join(' · ') }}</small></div><span :class="['badge', { disabled: !certificate.is_default }]">{{ certificate.is_default ? 'Default' : 'Named' }}</span><span :class="['badge', { disabled: !certificate.enabled }]">{{ certificate.enabled ? 'Active' : 'Disabled' }}</span><div class="row-actions"><button @click="openEditCertificate(certificate)">编辑</button><button class="danger" @click="removeCertificate(certificate)">删除</button></div></div>
          <div v-if="!certificates.length" class="empty-state">还没有证书。启用 HTTPS 前请先添加证书。</div>
        </section>
      </template>

      <template v-else-if="activeView === 'settings'">
        <div class="page-actions"><div><p>可信 CDN、流式上传、超时与后端连接池</p></div></div>
        <form class="panel settings-panel" @submit.prevent="saveSettings">
          <section class="settings-section"><p class="eyebrow">TRUSTED PROXIES</p><h2>可信代理与真实 IP</h2><p class="section-copy">只有 TCP 对端命中 Trusted Proxy CIDR 时，才会按下列顺序读取真实 IP Header。X-Forwarded-For 会按可信代理链从右向左解析，其他 Header 只接受单一合法 IP。</p><label>Trusted Proxy CIDR<textarea v-model="settingsDraft.trusted_proxy_cidrs_text" rows="6" placeholder="173.245.48.0/20&#10;2400:cb00::/32"></textarea></label><div class="header-priority"><div v-for="(header, index) in settingsDraft.real_ip_headers" :key="header" class="header-priority-row"><strong>{{ index + 1 }}</strong><code>{{ header }}</code><div class="row-actions"><button type="button" :disabled="index === 0" @click="moveRealIpHeader(index, -1)">↑</button><button type="button" :disabled="index === settingsDraft.real_ip_headers.length - 1" @click="moveRealIpHeader(index, 1)">↓</button><button type="button" class="danger" :disabled="settingsDraft.real_ip_headers.length === 1" @click="settingsDraft.real_ip_headers.splice(index, 1)">删除</button></div></div></div><div class="add-header"><input v-model.trim="settingsDraft.new_real_ip_header" placeholder="X-Real-Client-IP" pattern="[A-Za-z0-9_-]+" /><button type="button" class="ghost" @click="addRealIpHeader">＋ 添加 Header</button></div></section>
          <section class="settings-section"><p class="eyebrow">PROXY TRANSPORT</p><h2>双向流式转发与连接池</h2><div class="form-grid"><label>最大上传（MiB）<input v-model.number="settingsDraft.max_upload_mb" type="number" min="1" max="16384" required /></label><label>每个后端最大空闲连接<input v-model.number="settingsDraft.backend_pool_size" type="number" min="0" max="1024" :disabled="!settingsDraft.backend_keep_alive" required /></label><label>空闲连接 TTL（秒）<input v-model.number="settingsDraft.backend_idle_connection_ttl_seconds" type="number" min="1" max="86400" :disabled="!settingsDraft.backend_keep_alive" required /></label></div><label class="switch-line compact"><input v-model="settingsDraft.backend_keep_alive" type="checkbox" /><span>全局启用 Backend Keep-Alive、连接复用与零字节写失败安全重连</span></label><p class="section-copy">每个网站还可单独关闭 Keep-Alive。正常上传与下载复用一个按需分配的 16 KiB 传输块；Backend 提前响应与上传写入重叠时临时增加一个响应块；空闲连接到达 TTL 后会主动关闭；WebSocket Upgrade 成功后才分配双向隧道缓冲。</p></section>
          <section class="settings-section"><p class="eyebrow">TIMEOUTS</p><h2>超时设置</h2><p class="section-copy">所有值按秒保存并热更新。Body 与 Idle Timeout 是活动间隔限制，每次成功读写后都会重新计时，不限制整个大文件传输的总时长。Backend Connect 与 Response Header 已移到每个网站的反向代理配置。</p><div class="timeout-grid"><label>Client Header<input v-model.number="settingsDraft.client_header_timeout_seconds" type="number" min="1" max="86400" required /></label><label>Client Body<input v-model.number="settingsDraft.client_body_timeout_seconds" type="number" min="1" max="86400" required /></label><label>Client Write<input v-model.number="settingsDraft.client_write_timeout_seconds" type="number" min="1" max="86400" required /></label><label>Backend Idle I/O<input v-model.number="settingsDraft.backend_idle_timeout_seconds" type="number" min="1" max="86400" required /></label></div></section>
          <section class="settings-section"><p class="eyebrow">CONFIGURATION BACKUP</p><h2>配置备份 / 恢复</h2><p class="section-copy">导出站点、域名、策略、Backend、监听端口、证书与私钥、Trusted Proxy 和系统设置。管理员账号与登录会话不会被导出或覆盖。</p><div class="backup-actions"><button type="button" class="ghost" :disabled="backupBusy" @click="exportConfiguration">导出配置</button><button type="button" class="ghost" :disabled="backupBusy" @click="restoreInput?.click()">导入配置</button><input ref="restoreInput" class="hidden-file" type="file" accept="application/json,.json" @change="importConfiguration" /><span>备份含 TLS 私钥，请加密存放并限制访问。</span></div></section>
          <div class="modal-actions"><button class="primary" type="submit" :disabled="settingsSaving">{{ settingsSaving ? '保存中…' : '保存并热更新' }}</button></div>
        </form>
      </template>

      <template v-else-if="activeView === 'logs'">
        <div class="page-actions"><div><p>查看 access.log 与 error.log，结果按时间倒序显示</p></div><div class="log-actions"><select v-model.number="logLimit" @change="loadLogs"><option :value="100">最近 100 条</option><option :value="500">最近 500 条</option><option :value="1000">最近 1000 条</option></select><button class="ghost" @click="loadLogs">刷新</button></div></div>
        <section class="panel logs-panel"><div class="log-tabs"><button :class="{ active: logTab === 'access' }" @click="selectLogTab('access')">Access Log</button><button :class="{ active: logTab === 'error' }" @click="selectLogTab('error')">Error Log</button></div>
          <form v-if="logTab === 'access'" class="log-filters" @submit.prevent="loadLogs"><input v-model.trim="accessFilters.host" placeholder="域名" /><input v-model.trim="accessFilters.ip" placeholder="IP" /><input v-model.trim="accessFilters.status" inputmode="numeric" pattern="[0-9]*" placeholder="状态码" /><input v-model.trim="accessFilters.request_id" placeholder="Request ID" /><input v-model.trim="accessFilters.path" placeholder="路径" /><button class="primary" type="submit">搜索</button></form>
          <form v-else class="log-filters error-filters" @submit.prevent="loadLogs"><select v-model="errorFilters.level"><option value="">全部级别</option><option value="warning">warning</option><option value="error">error</option><option value="critical">critical</option></select><input v-model.trim="errorFilters.request_id" placeholder="Request ID" /><input v-model.trim="errorFilters.search" placeholder="组件或消息" /><button class="primary" type="submit">搜索</button></form>
          <div v-if="logsLoading" class="empty-state">正在读取日志…</div>
          <template v-else-if="logTab === 'access'"><div class="log-head access-log-grid"><span>时间</span><span>域名 / IP</span><span>请求</span><span>STATUS</span><span>延迟</span><span>Request ID</span></div><div v-for="entry in accessLogs" :key="entry.request_id + entry.timestamp" class="log-row access-log-grid"><span>{{ formatLogTime(entry.timestamp) }}</span><div><strong>{{ entry.host }}</strong><small>{{ entry.client_ip }}</small></div><div><code>{{ entry.method }}</code> {{ entry.path }}</div><span :class="['status-code', `s${Math.floor(entry.status / 100)}`]">{{ entry.status }}</span><span>{{ entry.duration_ms.toFixed(1) }} ms</span><code :title="entry.request_id">{{ entry.request_id }}</code></div><div v-if="!accessLogs.length" class="empty-state">没有符合条件的 Access Log。</div></template>
          <template v-else><div class="log-head error-log-grid"><span>时间</span><span>级别</span><span>组件</span><span>消息</span><span>Request ID</span></div><div v-for="(entry, index) in errorLogs" :key="entry.timestamp + index" class="log-row error-log-grid"><span>{{ formatLogTime(entry.timestamp) }}</span><span :class="['severity', entry.level]">{{ entry.level }}</span><code>{{ entry.component }}</code><span class="log-message">{{ entry.message }}</span><code :title="entry.request_id">{{ entry.request_id || '—' }}</code></div><div v-if="!errorLogs.length" class="empty-state">没有符合条件的 Error Log。</div></template>
        </section>
      </template>

      <template v-else-if="activeView === 'security'">
        <div class="page-actions"><div><p>规则按网站隔离，保存后原子热更新到新请求</p></div></div>
        <section class="panel policy-table"><div class="table-head policy-head"><span>网站</span><span>ACL</span><span>CC 防护</span><span>URL 鉴权</span><span>防盗链</span><span>Redirect</span><span></span></div>
          <div class="table-row policy-row" v-for="site in sites" :key="site.id"><div><strong>{{ site.name }}</strong><small>{{ site.domains.join(' · ') }}</small></div><span>{{ site.acl_rules.filter(rule => rule.enabled).length }} 条</span><span :class="['badge', { disabled: !site.rate_limit_enabled }]">{{ site.rate_limit_enabled ? `${site.rate_limit_max_requests}/${site.rate_limit_window_seconds}s` : 'Off' }}</span><span :class="['badge', { disabled: !site.url_auth_enabled }]">{{ site.url_auth_enabled ? (site.url_auth_scope === 'all' ? '全站' : `${site.url_auth_protected_uris.length} URI`) : 'Off' }}</span><span :class="['badge', { disabled: !site.hotlink_enabled }]">{{ site.hotlink_enabled ? 'On' : 'Off' }}</span><span>{{ site.redirect_rules.filter(rule => rule.enabled).length + (site.force_https ? 1 : 0) }} 条</span><div class="row-actions"><button @click="openEdit(site)">配置策略</button></div></div>
          <div v-if="!sites.length" class="empty-state">没有可配置的网站。</div>
        </section>
      </template>
    </section>
  </div>

  <div v-if="modalOpen" class="modal-backdrop" @click.self="modalOpen = false"><form class="modal" @submit.prevent="saveSite"><div class="modal-heading"><div><p class="eyebrow">SITE CONFIGURATION</p><h2>{{ draft.id ? '编辑网站' : '添加网站' }}</h2></div><button type="button" class="modal-close" @click="modalOpen = false">×</button></div>
    <div class="form-grid"><label class="span-2">网站名称<input v-model.trim="draft.name" required maxlength="128" placeholder="Example site" /></label><label class="span-2">域名（每行一个）<textarea v-model="draft.domains_text" required rows="3" placeholder="example.com&#10;www.example.com"></textarea></label></div>
    <section class="policy-section"><div class="section-heading"><div><p class="eyebrow">REVERSE PROXY</p><h3>反向代理</h3></div></div><p class="section-copy">上游地址支持 IPv4、IPv6 或 DNS 主机名。Host 留在“自动”时保留客户端 Host；HTTPS 的 SNI 留空时使用自定义 Host，未自定义时使用上游地址。</p>
      <div class="form-grid"><label>上游协议<select v-model="draft.backend_protocol" @change="changeBackendProtocol"><option value="http">HTTP</option><option value="https">HTTPS</option></select></label><label>上游地址<input v-model.trim="draft.backend_address" required placeholder="127.0.0.1 或 www.example.com" /></label><label>上游端口<input v-model.number="draft.backend_port" type="number" min="1" max="65535" required /></label><label>上游 Host<select :value="draft.backend_host ? 'custom' : 'auto'" @change="setBackendHostMode"><option value="auto">自动</option><option value="custom">自定义</option></select></label><label v-if="draft.backend_host" class="span-2">自定义 Host<input v-model.trim="draft.backend_host" required placeholder="www.example.com" /></label><label>连接超时<input v-model.number="draft.backend_connect_timeout_seconds" type="number" min="1" max="86400" required /><small>秒</small></label><label>响应超时<input v-model.number="draft.backend_response_timeout_seconds" type="number" min="1" max="86400" required /><small>秒</small></label><template v-if="draft.backend_protocol === 'https'"><label class="span-2">TLS SNI<input v-model.trim="draft.backend_tls_sni" placeholder="自动（跟随上游 Host）" /></label></template></div>
      <div class="check-row compact"><label><input v-model="draft.backend_keep_alive" type="checkbox" /> Backend Keep-Alive</label><label v-if="draft.backend_protocol === 'https'"><input v-model="draft.backend_tls_verify_certificate" type="checkbox" /> 验证上游证书</label></div>
      <div class="backend-test-line"><button type="button" class="ghost" :disabled="backendTesting" @click="testBackend">{{ backendTesting ? '测试中…' : '测试连接' }}</button><span v-if="backendTestResult" :class="['test-result', { failed: !backendTestResult.success }]">{{ backendTestResult.success ? `连接成功 · ${backendTestResult.remote_address}:${backendTestResult.remote_port} · ${backendTestResult.latency_ms.toFixed(1)} ms${backendTestResult.tls_verified ? ' · 证书已验证' : ''}` : `连接失败：${backendTestResult.error}` }}</span></div>
    </section>
    <div class="protocol-card"><label class="switch-line"><input v-model="draft.http_enabled" type="checkbox" /><span>启用 HTTP</span></label><label>端口<input v-model.number="draft.http_port" type="number" min="1" max="65535" :disabled="!draft.http_enabled" /></label></div>
    <div class="protocol-card"><label class="switch-line"><input v-model="draft.https_enabled" type="checkbox" /><span>启用 HTTPS</span></label><label>端口<input v-model.number="draft.https_port" type="number" min="1" max="65535" :disabled="!draft.https_enabled" /></label></div>
    <div class="check-row"><label><input v-model="draft.enabled" type="checkbox" /> 启用网站</label><label><input v-model="draft.force_https" type="checkbox" :disabled="!draft.https_enabled" /> HTTP 强制跳转 HTTPS</label></div>

    <section class="policy-section"><div class="section-heading"><div><p class="eyebrow">BACKEND OVERLOAD</p><h3>Backend 并发过载保护</h3></div></div><p class="section-copy">活动连接达到上限后进入等待队列；队列已满或等待超时返回 503。配额按本站隔离，并覆盖普通 HTTP 与 WebSocket。</p><div class="form-grid"><label>最大活动连接<input v-model.number="draft.backend_max_active_connections" type="number" min="1" max="100000" required /></label><label>最大等待请求<input v-model.number="draft.backend_max_queue" type="number" min="0" max="1000000" required /></label><label>等待超时（秒）<input v-model.number="draft.backend_queue_timeout_seconds" type="number" min="1" max="86400" required /></label></div></section>

    <section class="policy-section"><div class="section-heading"><div><p class="eyebrow">ACCESS CONTROL</p><h3>ACL 规则</h3></div><button type="button" class="ghost" @click="addAclRule">＋ 添加规则</button></div>
      <p class="section-copy">规则按顺序匹配；一条规则内的条件使用 AND。Regex 与 CIDR 在热更新时预编译/解析。</p>
      <article class="rule-card" v-for="(rule, ruleIndex) in draft.acl_rules" :key="ruleIndex"><div class="rule-title"><label class="switch-line"><input v-model="rule.enabled" type="checkbox" /><span>启用</span></label><input v-model.trim="rule.name" required maxlength="128" placeholder="Block Git" /><button type="button" class="danger-text" @click="draft.acl_rules.splice(ruleIndex, 1)">删除</button></div>
        <div class="condition-row" v-for="(condition, conditionIndex) in rule.conditions" :key="conditionIndex"><span class="if-mark">{{ conditionIndex ? 'AND' : 'IF' }}</span><select v-model="condition.field" @change="normalizeAclCondition(condition)"><option value="ip">IP</option><option value="uri">URI</option><option value="host">Host</option><option value="method">Method</option><option value="user_agent">User-Agent</option><option value="referer">Referer</option><option value="header">Header</option></select><input v-if="condition.field === 'header'" v-model.trim="condition.header_name" required placeholder="X-Custom-Header" /><select v-model="condition.operator" @change="normalizeAclCondition(condition)"><option value="equal">等于</option><option value="not_equal">不等于</option><option value="contains">包含</option><option value="not_contains">不包含</option><option value="starts_with">开头是</option><option value="ends_with">结尾是</option><option value="regex">Regex</option><option v-if="condition.field === 'ip'" value="in_cidr">属于 CIDR</option><option v-if="condition.field === 'ip'" value="not_in_cidr">不属于 CIDR</option></select><input v-model.trim="condition.value" required :placeholder="isCidrOperator(condition.operator) ? '192.168.0.0/16 或 2400:cb00::/32' : '匹配值'" /><label v-if="!isCidrOperator(condition.operator)" class="case-check"><input v-model="condition.case_sensitive" type="checkbox" /> Aa</label><span v-else class="case-check">IP</span><button v-if="rule.conditions.length > 1" type="button" class="icon-danger" @click="rule.conditions.splice(conditionIndex, 1)">×</button></div>
        <div class="rule-action"><button v-if="rule.conditions.length < 8" type="button" class="link-button" @click="addAclCondition(rule)">＋ 添加 AND 条件</button><span>THEN</span><select v-model="rule.action" @change="normalizeAclAction(rule)"><option value="allow">Allow</option><option value="deny">Deny</option><option value="return">Return</option><option value="redirect">Redirect</option></select><select v-if="rule.action !== 'allow'" v-model.number="rule.status"><template v-if="rule.action === 'redirect'"><option :value="301">301</option><option :value="302">302</option><option :value="307">307</option><option :value="308">308</option></template><template v-else><option :value="403">403</option><option :value="404">404</option><option :value="429">429</option></template></select><input v-if="rule.action === 'redirect'" v-model.trim="rule.redirect_location" required placeholder="https://example.com/blocked" /></div>
      </article><div v-if="!draft.acl_rules.length" class="inline-empty">未配置 ACL，请求将继续执行其他策略。</div>
    </section>

    <section class="policy-section"><div class="section-heading"><div><p class="eyebrow">RATE LIMIT</p><h3>基础 CC 防护</h3></div><label class="switch-line"><input v-model="draft.rate_limit_enabled" type="checkbox" /><span>启用</span></label></div>
      <div class="form-grid"><label>时间窗口（秒）<input v-model.number="draft.rate_limit_window_seconds" type="number" min="1" max="3600" :disabled="!draft.rate_limit_enabled" /></label><label>最大请求数<input v-model.number="draft.rate_limit_max_requests" type="number" min="1" max="1000000" :disabled="!draft.rate_limit_enabled" /></label><label>临时封禁（秒，0 表示不封禁）<input v-model.number="draft.rate_limit_ban_seconds" type="number" min="0" max="86400" :disabled="!draft.rate_limit_enabled" /></label></div>
    </section>

    <section class="policy-section"><div class="section-heading"><div><p class="eyebrow">URL AUTH · ALIBABA CLOUD TYPE A</p><h3>URL 鉴权</h3></div><label class="switch-line"><input v-model="draft.url_auth_enabled" type="checkbox" /><span>启用</span></label></div>
      <p class="section-copy">兼容阿里云 A 方式：<code>auth_key=timestamp-rand-uid-md5hash</code>。ACL、限流和重定向完成后验签，成功后移除保留签名参数 <code>auth_key/sign/time</code> 再进入 Backend Limiter。</p>
      <div class="form-grid"><label>保护范围<select v-model="draft.url_auth_scope" :disabled="!draft.url_auth_enabled"><option value="all">全站所有 URI</option><option value="specified">仅指定 URI</option></select></label><label>有效期（秒）<input v-model.number="draft.url_auth_validity_seconds" type="number" min="1" max="31536000" required :disabled="!draft.url_auth_enabled" /></label><label>主 KEY<input v-model.trim="draft.url_auth_primary_key" type="password" minlength="6" maxlength="128" pattern="[A-Za-z0-9]*" autocomplete="new-password" :required="draft.url_auth_enabled && !draft.url_auth_backup_key" :disabled="!draft.url_auth_enabled" placeholder="6～128 位字母或数字" /></label><label>备 KEY<input v-model.trim="draft.url_auth_backup_key" type="password" minlength="6" maxlength="128" pattern="[A-Za-z0-9]*" autocomplete="new-password" :required="draft.url_auth_enabled && !draft.url_auth_primary_key" :disabled="!draft.url_auth_enabled" placeholder="轮换期间可并行使用" /></label></div>
      <template v-if="draft.url_auth_scope === 'specified'"><div class="section-heading uri-auth-heading"><p class="section-copy">URI 只匹配 URL 编码后的 path，不包含查询参数；前缀匹配适合保护整个目录。</p><button type="button" class="ghost" :disabled="!draft.url_auth_enabled" @click="addUrlAuthUri">＋ 添加 URI</button></div><div class="url-auth-row" v-for="(rule, ruleIndex) in draft.url_auth_protected_uris" :key="ruleIndex"><select v-model="rule.match" :disabled="!draft.url_auth_enabled"><option value="exact">精确匹配</option><option value="prefix">前缀匹配</option></select><input v-model.trim="rule.path" required maxlength="8192" :disabled="!draft.url_auth_enabled" placeholder="/video/" /><button type="button" class="icon-danger" :disabled="!draft.url_auth_enabled" @click="draft.url_auth_protected_uris.splice(ruleIndex, 1)">×</button></div><div v-if="!draft.url_auth_protected_uris.length" class="inline-empty">指定 URI 模式至少需要一条规则。</div></template>
    </section>

    <section class="policy-section"><div class="section-heading"><div><p class="eyebrow">HOTLINK PROTECTION</p><h3>Referer 防盗链</h3></div><label class="switch-line"><input v-model="draft.hotlink_enabled" type="checkbox" /><span>启用</span></label></div>
      <div class="form-grid"><label class="span-2">保护扩展名（逗号分隔）<input v-model="draft.hotlink_extensions_text" :disabled="!draft.hotlink_enabled" placeholder="jpg, png, mp4, zip" /></label><label class="span-2">额外允许的 Referer 域名（每行一个，本站域名自动允许）<textarea v-model="draft.hotlink_allowed_hosts_text" rows="2" :disabled="!draft.hotlink_enabled" placeholder="static.example.com&#10;*.trusted.example"></textarea></label><label class="span-2">拒绝时跳转地址（留空返回 403）<input v-model.trim="draft.hotlink_redirect_location" :disabled="!draft.hotlink_enabled" placeholder="https://example.com/no-hotlink.png" /></label></div><label class="switch-line compact"><input v-model="draft.hotlink_allow_empty_referer" type="checkbox" :disabled="!draft.hotlink_enabled" /><span>允许空 Referer（浏览器直接访问）</span></label>
    </section>

    <section class="policy-section"><div class="section-heading"><div><p class="eyebrow">REDIRECTS</p><h3>自定义重定向</h3></div><button type="button" class="ghost" @click="addRedirectRule">＋ 添加规则</button></div>
      <article class="rule-card redirect-card" v-for="(rule, ruleIndex) in draft.redirect_rules" :key="ruleIndex"><div class="rule-title"><label class="switch-line"><input v-model="rule.enabled" type="checkbox" /><span>启用</span></label><input v-model.trim="rule.name" required maxlength="128" placeholder="www to apex" /><button type="button" class="danger-text" @click="draft.redirect_rules.splice(ruleIndex, 1)">删除</button></div><div class="redirect-grid"><label>来源 Host（空表示全部）<input v-model.trim="rule.source_host" placeholder="www.example.com" /></label><label>来源路径<input v-model.trim="rule.source_path" required placeholder="/old" /></label><label>匹配方式<select v-model="rule.match"><option value="exact">精确</option><option value="prefix">前缀</option></select></label><label>状态码<select v-model.number="rule.status"><option :value="301">301</option><option :value="302">302</option><option :value="307">307</option><option :value="308">308</option></select></label><label class="span-2">目标地址<input v-model.trim="rule.destination" required placeholder="/new 或 https://example.com" /></label></div><div class="check-row compact"><label><input v-model="rule.preserve_path" type="checkbox" /> 保留匹配后的路径</label><label><input v-model="rule.preserve_query" type="checkbox" /> 保留查询参数</label></div></article><div v-if="!draft.redirect_rules.length" class="inline-empty">未配置自定义重定向。</div>
    </section>

    <p v-if="errorMessage" class="form-error">{{ errorMessage }}</p><div class="modal-actions"><button type="button" class="ghost" @click="modalOpen = false">取消</button><button class="primary" type="submit" :disabled="saving">{{ saving ? '保存中…' : '保存配置' }}</button></div></form></div>

  <div v-if="certificateModalOpen" class="modal-backdrop" @click.self="certificateModalOpen = false"><form class="modal certificate-modal" @submit.prevent="saveCertificate"><div class="modal-heading"><div><p class="eyebrow">TLS CERTIFICATE</p><h2>{{ certificateDraft.id ? '编辑证书' : '添加证书' }}</h2></div><button type="button" class="modal-close" @click="certificateModalOpen = false">×</button></div>
    <div class="form-grid"><label class="span-2">证书名称<input v-model.trim="certificateDraft.name" required maxlength="128" placeholder="example.com 2026" /></label><label class="span-2">绑定域名（每行一个，支持 *.example.com）<textarea v-model="certificateDraft.domains_text" required rows="3" placeholder="example.com&#10;www.example.com"></textarea></label></div>
    <section class="policy-section"><div class="section-heading"><div><p class="eyebrow">CRT / PEM</p><h3>证书链</h3></div><label class="file-button">选择 .crt / .pem<input type="file" accept=".crt,.pem,application/x-pem-file" @change="readPemFile($event, 'certificate_pem')" /></label></div><textarea v-model="certificateDraft.certificate_pem" required rows="10" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></section>
    <section class="policy-section"><div class="section-heading"><div><p class="eyebrow">PRIVATE KEY</p><h3>私钥</h3></div><label class="file-button">选择 .key / .pem<input type="file" accept=".key,.pem,application/x-pem-file" @change="readPemFile($event, 'private_key_pem')" /></label></div><p v-if="certificateDraft.id" class="section-copy">留空会保留当前私钥；填写新私钥会先校验是否与证书匹配。</p><textarea v-model="certificateDraft.private_key_pem" :required="!certificateDraft.id" rows="10" spellcheck="false" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></section>
    <div class="check-row"><label><input v-model="certificateDraft.enabled" type="checkbox" /> 启用证书</label><label><input v-model="certificateDraft.is_default" type="checkbox" /> 设为无 SNI 时的默认证书</label></div><div class="modal-actions"><button type="button" class="ghost" @click="certificateModalOpen = false">取消</button><button class="primary" type="submit" :disabled="saving">{{ saving ? '校验并保存中…' : '校验、保存并热更新' }}</button></div></form></div>
</template>
