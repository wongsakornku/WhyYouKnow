import { useEffect, useState } from 'react'
import {
  Ban,
  Bot,
  Check,
  CheckCircle2,
  Copy,
  Download,
  Edit3,
  Eye,
  FileSpreadsheet,
  FileText,
  KeyRound,
  Lock,
  LogOut,
  Mail,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  TrendingUp,
  Unlock,
  UserCheck,
  UserPlus,
  Users,
  X,
} from 'lucide-react'
import { api } from '../api'
import type {
  AdminUserDetails,
  AdminUserListItem,
  AppInvite,
  AppUser,
  AttackProtectionConfig,
  AuditLog,
  OAuthClient,
  UserProfile,
} from '../types/auth'

interface AdminPageProps {
  initialTab?: 'apps' | 'app_users' | 'all_users' | 'audit_logs'
}

export default function AdminPage({ initialTab = 'apps' }: AdminPageProps = {}) {
  const [tab, setTab] = useState<'apps' | 'app_users' | 'all_users' | 'audit_logs'>(initialTab)
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null)
  const [clients, setClients] = useState<OAuthClient[] | null>(null)
  const [allUsers, setAllUsers] = useState<AdminUserListItem[] | null>(null)
  const [selectedClientId, setSelectedClientId] = useState<string>('')
  const [appUsers, setAppUsers] = useState<AppUser[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [denied, setDenied] = useState(false)

  // New Client Form state
  const [showAddForm, setShowAddForm] = useState(false)
  const [clientName, setClientName] = useState('')
  const [redirectUris, setRedirectUris] = useState('')
  const [isConfidential, setIsConfidential] = useState(true)
  const [createdSecret, setCreatedSecret] = useState<{
    id: string
    secret: string | null
    name: string
  } | null>(null)
  const [copiedId, setCopiedId] = useState(false)
  const [copiedSecret, setCopiedSecret] = useState(false)

  // Client Edit Modal state
  const [editingClient, setEditingClient] = useState<OAuthClient | null>(null)
  const [editName, setEditName] = useState('')
  const [editRedirectUris, setEditRedirectUris] = useState('')
  const [savingClient, setSavingClient] = useState(false)

  // Rotate Secret Modal state
  const [rotatedSecretData, setRotatedSecretData] = useState<{
    clientId: string
    clientSecret: string
  } | null>(null)
  const [copiedRotatedSecret, setCopiedRotatedSecret] = useState(false)

  // Attack Protection Modal state
  const [attackModalClient, setAttackModalClient] = useState<OAuthClient | null>(null)
  const [attackConfig, setAttackConfig] = useState<AttackProtectionConfig>({
    bot_detection: false,
    suspicious_ip_throttling: true,
    brute_force_protection: true,
    suspicious_account_shield: false,
  })
  const [savingAttackProtection, setSavingAttackProtection] = useState(false)

  const handleOpenAttackModal = (client: OAuthClient) => {
    setAttackModalClient(client)
    setAttackConfig(client.attack_protection || {
      bot_detection: false,
      suspicious_ip_throttling: true,
      brute_force_protection: true,
      suspicious_account_shield: false,
    })
  }

  const handleToggleAttackProtection = async (key: keyof AttackProtectionConfig) => {
    if (!attackModalClient) return
    const nextVal = !attackConfig[key]
    const updated = { ...attackConfig, [key]: nextVal }
    setAttackConfig(updated)
    setSavingAttackProtection(true)
    try {
      const res = await api.adminUpdateAttackProtection(attackModalClient.client_id, { [key]: nextVal })
      setClients((prev) =>
        prev
          ? prev.map((c) =>
              c.client_id === attackModalClient.client_id
                ? { ...c, attack_protection: res.attack_protection }
                : c
            )
          : null
      )
      setAttackConfig(res.attack_protection)
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'อัปเดตการตั้งค่าไม่สำเร็จ')
      setAttackConfig(attackConfig)
    } finally {
      setSavingAttackProtection(false)
    }
  }

  // App Invites Modal state
  const [inviteModalClient, setInviteModalClient] = useState<OAuthClient | null>(null)
  const [invites, setInvites] = useState<AppInvite[]>([])
  const [invitesLoading, setInvitesLoading] = useState(false)
  const [newInviteEmail, setNewInviteEmail] = useState('')
  const [newInviteRole, setNewInviteRole] = useState<'admin' | 'member' | 'viewer'>('member')
  const [addingInvite, setAddingInvite] = useState(false)

  // User Details Modal state
  const [inspectingUser, setInspectingUser] = useState<AdminUserDetails | null>(null)
  const [inspectingLoading, setInspectingLoading] = useState(false)

  // User Search state
  const [userSearch, setUserSearch] = useState('')

  // Audit Logs state
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([])
  const [auditTotal, setAuditTotal] = useState(0)
  const [auditSearch, setAuditSearch] = useState('')
  const [auditEventType, setAuditEventType] = useState('')
  const [auditClientId, setAuditClientId] = useState('')
  const [auditOffset, setAuditOffset] = useState(0)
  const [auditLoading, setAuditLoading] = useState(false)
  const AUDIT_LIMIT = 25

  const loadInitial = () => {
    setLoading(true)
    Promise.all([api.me(), api.adminClients(), api.adminUsers()])
      .then(([me, cls, us]) => {
        setCurrentUser(me)
        setClients(cls)
        setAllUsers(us)
        if (cls.length > 0 && !selectedClientId) {
          setSelectedClientId(cls[0].client_id)
        }
      })
      .catch(() => setDenied(true))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadInitial()
  }, [])

  const loadAppUsers = (cId: string) => {
    if (!cId) return
    api
      .adminGetAppUsers(cId)
      .then(setAppUsers)
      .catch(() => setAppUsers([]))
  }

  useEffect(() => {
    if (selectedClientId && tab === 'app_users') {
      loadAppUsers(selectedClientId)
    }
  }, [selectedClientId, tab])

  // Load Audit Logs
  const loadAuditLogs = () => {
    setAuditLoading(true)
    api
      .adminGetAuditLogs({
        q: auditSearch || undefined,
        event_type: auditEventType || undefined,
        client_id: auditClientId || undefined,
        limit: AUDIT_LIMIT,
        offset: auditOffset,
      })
      .then((res) => {
        setAuditLogs(res.logs)
        setAuditTotal(res.total)
      })
      .catch(() => setAuditLogs([]))
      .finally(() => setAuditLoading(false))
  }

  useEffect(() => {
    if (tab === 'audit_logs') {
      loadAuditLogs()
    }
  }, [tab, auditEventType, auditClientId, auditOffset])

  const handleAuditSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setAuditOffset(0)
    loadAuditLogs()
  }

  const handleExport = (format: 'csv' | 'json') => {
    const url = api.adminExportAuditLogsUrl({
      q: auditSearch || undefined,
      event_type: auditEventType || undefined,
      client_id: auditClientId || undefined,
      format,
    })
    window.open(url, '_blank')
  }

  const handleCreateClient = async (e: React.FormEvent) => {
    e.preventDefault()
    const uris = redirectUris
      .split('\n')
      .map((u) => u.trim())
      .filter(Boolean)
    if (!clientName.trim() || uris.length === 0) return

    try {
      const res = await api.adminCreateClient({
        client_name: clientName.trim(),
        redirect_uris: uris,
        is_confidential: isConfidential,
      })
      setCreatedSecret({
        id: res.client_id,
        secret: res.client_secret,
        name: res.client_name,
      })
      setClientName('')
      setRedirectUris('')
      setShowAddForm(false)
      loadInitial()
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'สร้างแอปไม่สำเร็จ')
    }
  }

  const handleOpenEditClient = (c: OAuthClient) => {
    setEditingClient(c)
    setEditName(c.client_name)
    setEditRedirectUris(c.redirect_uris.join('\n'))
  }

  const handleSaveEditClient = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editingClient) return
    const uris = editRedirectUris
      .split('\n')
      .map((u) => u.trim())
      .filter(Boolean)
    if (!editName.trim() || uris.length === 0) return

    setSavingClient(true)
    try {
      await api.adminUpdateClient(editingClient.client_id, {
        client_name: editName.trim(),
        redirect_uris: uris,
      })
      setEditingClient(null)
      loadInitial()
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'อัปเดตแอปไม่สำเร็จ')
    } finally {
      setSavingClient(false)
    }
  }

  const handleToggleClientActive = async (client: OAuthClient) => {
    const nextState = !client.is_active
    const confirmMsg = nextState
      ? `ต้องการเปิดใช้งานแอป "${client.client_name}" หรือไม่?`
      : `ยืนยันการระงับใช้งานแอป "${client.client_name}" ชั่วคราว? ผู้ใช้จะไม่สามารถล็อกอินผ่านแอปนี้ได้จนกว่าจะเปิดใช้งานอีกครั้ง`
    if (!confirm(confirmMsg)) return

    try {
      await api.adminUpdateClient(client.client_id, { is_active: nextState })
      loadInitial()
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'เปลี่ยนสถานะแอปไม่สำเร็จ')
    }
  }

  const handleToggleAccessMode = async (client: OAuthClient) => {
    const nextMode = client.access_mode === 'open' ? 'invite_only' : 'open'
    const confirmMsg =
      nextMode === 'invite_only'
        ? `เปลี่ยนเป็นโหมด "เฉพาะผู้ได้รับเชิญ (Invite Only)"? เฉพาะอีเมลที่อยู่ในรายชื่อคำเชิญเท่านั้นที่จะสามารถล็อกอินแอปนี้ได้`
        : `เปลี่ยนเป็นโหมด "เปิดรับทุกคน (Open)"? ผู้ใช้ทุกคนในระบบจะสามารถล็อกอินเข้าแอปนี้ได้`
    if (!confirm(confirmMsg)) return

    try {
      await api.adminUpdateClient(client.client_id, { access_mode: nextMode })
      loadInitial()
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'เปลี่ยนโหมดไม่สำเร็จ')
    }
  }

  const handleRotateSecret = async (client: OAuthClient) => {
    if (!client.is_confidential) return
    const confirmMsg = `ยืนยันการสลับ Client Secret ใหม่สำหรับ "${client.client_name}" หรือไม่? Secret เก่าจะถูกยกเลิกทันทีและคุณต้องอัปเดต Secret ในการตั้งค่าของ ${client.client_name}`
    if (!confirm(confirmMsg)) return

    try {
      const res = await api.adminRotateClientSecret(client.client_id)
      setRotatedSecretData({
        clientId: res.client_id,
        clientSecret: res.client_secret,
      })
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Rotate Secret ไม่สำเร็จ')
    }
  }

  // App Invites Handlers
  const handleOpenInvitesModal = async (client: OAuthClient) => {
    setInviteModalClient(client)
    setInvitesLoading(true)
    try {
      const list = await api.adminGetAppInvites(client.client_id)
      setInvites(list)
    } catch {
      setInvites([])
    } finally {
      setInvitesLoading(false)
    }
  }

  const handleAddInvite = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!inviteModalClient || !newInviteEmail.trim()) return

    setAddingInvite(true)
    try {
      await api.adminAddAppInvite(inviteModalClient.client_id, {
        email: newInviteEmail.trim(),
        initial_role: newInviteRole,
      })
      setNewInviteEmail('')
      const list = await api.adminGetAppInvites(inviteModalClient.client_id)
      setInvites(list)
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'เพิ่มคำเชิญไม่สำเร็จ')
    } finally {
      setAddingInvite(false)
    }
  }

  const handleDeleteInvite = async (inviteId: number) => {
    if (!inviteModalClient) return
    if (!confirm('ต้องการลบคำเชิญนี้หรือไม่?')) return

    try {
      await api.adminDeleteAppInvite(inviteModalClient.client_id, inviteId)
      const list = await api.adminGetAppInvites(inviteModalClient.client_id)
      setInvites(list)
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'ลบคำเชิญไม่สำเร็จ')
    }
  }

  const handleDeleteClient = async (clientId: string) => {
    if (!confirm(`ยืนยันการลบแอป "${clientId}" หรือไม่? ผู้ใช้และ Token ที่เกี่ยวข้องจะถูกลบทั้งหมด`)) return
    try {
      await api.adminDeleteClient(clientId)
      loadInitial()
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'ลบแอปไม่สำเร็จ')
    }
  }

  const handleRoleChange = async (userId: number, newRole: string) => {
    try {
      await api.adminUpdateAppUserRole(selectedClientId, userId, newRole)
      loadAppUsers(selectedClientId)
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'เปลี่ยนสิทธิ์ไม่สำเร็จ')
    }
  }

  const handleStatusToggle = async (userId: number, currentStatus: string) => {
    const nextStatus = currentStatus === 'active' ? 'revoked' : 'active'
    const promptMsg =
      nextStatus === 'revoked'
        ? 'ยืนยันการตัดสิทธิ์ (Revoke) ผู้ใช้นี้ออกจากแอปนี้หรือไม่? Token ทั้งหมดของเขาจะถูกยกเลิกทันที'
        : 'คืนสิทธิ์การเข้าใช้งานแอปนี้ให้ผู้ใช้คนนี้หรือไม่?'
    if (!confirm(promptMsg)) return

    try {
      await api.adminUpdateAppUserStatus(selectedClientId, userId, nextStatus)
      loadAppUsers(selectedClientId)
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'อัปเดตสถานะไม่สำเร็จ')
    }
  }

  // Global User Management Handlers
  const handleInspectUser = async (userId: number) => {
    setInspectingLoading(true)
    setInspectingUser(null)
    try {
      const details = await api.adminGetUserDetails(userId)
      setInspectingUser(details)
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'โหลดข้อมูลผู้ใช้ไม่สำเร็จ')
    } finally {
      setInspectingLoading(false)
    }
  }

  const handleForceLogoutUser = async (user: AdminUserListItem) => {
    const confirmMsg = `ยืนยันการบังคับให้ออกจากระบบทั้งหมด (Force Logout) สำหรับ "${user.email}" หรือไม่? Session และ OAuth Token ทุกแอปจะถูกยกเลิกทันที`
    if (!confirm(confirmMsg)) return

    try {
      const res = await api.adminForceLogoutUser(user.id)
      alert(`บังคับออกจากระบบสำเร็จ (ลบ ${res.revoked_sessions} session, ${res.revoked_tokens} tokens)`)
      if (inspectingUser && inspectingUser.user.id === user.id) {
        handleInspectUser(user.id)
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'ดำเนินการไม่สำเร็จ')
    }
  }

  const handleToggleSuspendUser = async (user: AdminUserListItem) => {
    const isSuspending = user.status === 'active'
    const confirmMsg = isSuspending
      ? `ยืนยันการระงับบัญชี (Suspend) ของ "${user.email}" หรือไม่? ผู้ใช้จะไม่สามารถเข้าสู่ระบบหรือเรียกใช้ Token ใดๆ ได้`
      : `ยืนยันการปลดระงับบัญชี (Unsuspend) ของ "${user.email}" หรือไม่?`
    if (!confirm(confirmMsg)) return

    try {
      if (isSuspending) {
        await api.adminSuspendUser(user.id)
      } else {
        await api.adminUnsuspendUser(user.id)
      }
      loadInitial()
      if (inspectingUser && inspectingUser.user.id === user.id) {
        handleInspectUser(user.id)
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'ดำเนินการไม่สำเร็จ')
    }
  }

  const handleToggleAdminStatus = async (user: AdminUserListItem) => {
    const nextAdmin = !user.is_admin
    const confirmMsg = nextAdmin
      ? `ต้องการแต่งตั้ง "${user.email}" เป็น Admin ของระบบหรือไม่?`
      : `ต้องการถอดสิทธิ์ Admin ของ "${user.email}" หรือไม่?`
    if (!confirm(confirmMsg)) return

    try {
      await api.adminSetUserAdmin(user.id, nextAdmin)
      loadInitial()
      if (inspectingUser && inspectingUser.user.id === user.id) {
        handleInspectUser(user.id)
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'เปลี่ยนสิทธิ์ Admin ไม่สำเร็จ')
    }
  }

  const getEventBadge = (type: string) => {
    switch (type) {
      case 'LOGIN':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200'
      case 'LOGOUT':
      case 'FORCE_LOGOUT':
        return 'bg-slate-100 text-slate-700 border-slate-200'
      case 'OAUTH_AUTHORIZE':
        return 'bg-blue-50 text-blue-700 border-blue-200'
      case 'OAUTH_TOKEN':
      case 'OAUTH_TOKEN_REFRESH':
        return 'bg-indigo-50 text-indigo-700 border-indigo-200'
      case 'OAUTH_TOKEN_REVOKE':
      case 'REFRESH_TOKEN_REUSE_DETECTED':
        return 'bg-rose-50 text-rose-700 border-rose-200'
      case 'ROLE_UPDATED':
      case 'ADMIN_GRANTED':
      case 'ADMIN_REVOKED':
        return 'bg-amber-50 text-amber-700 border-amber-200'
      case 'STATUS_UPDATED':
      case 'USER_SUSPENDED':
      case 'CLIENT_DELETED':
      case 'ACCOUNT_DELETED':
        return 'bg-red-50 text-red-700 border-red-200'
      case 'USER_UNSUSPENDED':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200'
      case 'CLIENT_CREATED':
      case 'CLIENT_UPDATED':
      case 'CLIENT_SECRET_ROTATED':
        return 'bg-purple-50 text-purple-700 border-purple-200'
      case 'INVITE_CREATED':
      case 'INVITE_DELETED':
      case 'INVITE_CLAIMED':
        return 'bg-cyan-50 text-cyan-700 border-cyan-200'
      default:
        return 'bg-slate-50 text-slate-700 border-slate-200'
    }
  }

  const filteredUsers = allUsers?.filter((u) => {
    if (!userSearch.trim()) return true
    const q = userSearch.toLowerCase()
    return u.email.toLowerCase().includes(q) || u.name.toLowerCase().includes(q)
  })

  if (denied) return <p className="rounded-lg bg-red-50 p-3 text-sm text-red-600">ไม่มีสิทธิ์เข้าถึง (เฉพาะ Admin)</p>
  if (loading && !clients) return <p className="text-sm text-slate-500">กำลังโหลด...</p>

  return (
    <div className="space-y-4">
      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-200 pb-2">
        <button
          onClick={() => setTab('apps')}
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
            tab === 'apps' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:bg-slate-200'
          }`}
        >
          <KeyRound className="h-4 w-4" /> แอปพลิเคชัน OAuth ({clients?.length || 0})
        </button>

        <button
          onClick={() => setTab('app_users')}
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
            tab === 'app_users' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:bg-slate-200'
          }`}
        >
          <UserCheck className="h-4 w-4" /> จัดการสิทธิ์รายแอป (Users by App)
        </button>

        <button
          onClick={() => setTab('all_users')}
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
            tab === 'all_users' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:bg-slate-200'
          }`}
        >
          <Users className="h-4 w-4" /> ผู้ใช้ทั้งหมด ({allUsers?.length || 0})
        </button>

        <button
          onClick={() => setTab('audit_logs')}
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
            tab === 'audit_logs' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:bg-slate-200'
          }`}
        >
          <FileText className="h-4 w-4" /> บันทึกกิจกรรม (Audit Logs)
        </button>
      </div>

      {/* TAB 1: OAuth Apps */}
      {tab === 'apps' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-slate-800">แอปพลิเคชันภายนอกที่เชื่อมต่อ</h2>
              <p className="text-xs text-slate-500">จัดการ Client Credentials, สถานะเปิด/ปิด, และการจำกัดสิทธิ์ Invite Only</p>
            </div>
            <button
              onClick={() => setShowAddForm(!showAddForm)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700"
            >
              <Plus className="h-4 w-4" /> ลงทะเบียนแอปใหม่
            </button>
          </div>

          {/* New App Secret Alert */}
          {createdSecret && (
            <div className="rounded-2xl border border-amber-300 bg-amber-50 p-5 shadow-sm">
              <h3 className="font-semibold text-amber-900">
                บันทึกแอป "{createdSecret.name}" สำเร็จ!
              </h3>
              <p className="mt-1 text-xs text-amber-700">
                กรุณาคัดลอก Client ID และ Secret ไว้ใช้งานทันที (Secret จะไม่แสดงอีกครั้ง)
              </p>
              <div className="mt-3 space-y-2 text-xs">
                <div>
                  <span className="font-semibold text-amber-900">Client ID:</span>
                  <div className="mt-1 flex items-center gap-2">
                    <input
                      readOnly
                      value={createdSecret.id}
                      className="w-full rounded bg-white p-2 font-mono border border-amber-200 text-slate-800"
                    />
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(createdSecret.id)
                        setCopiedId(true)
                        setTimeout(() => setCopiedId(false), 2000)
                      }}
                      className="rounded bg-amber-200 px-3 py-2 text-amber-900 hover:bg-amber-300"
                    >
                      {copiedId ? <Check className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                {createdSecret.secret && (
                  <div>
                    <span className="font-semibold text-amber-900">Client Secret:</span>
                    <div className="mt-1 flex items-center gap-2">
                      <input
                        readOnly
                        value={createdSecret.secret}
                        className="w-full rounded bg-white p-2 font-mono border border-amber-200 text-slate-800"
                      />
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(createdSecret.secret!)
                          setCopiedSecret(true)
                          setTimeout(() => setCopiedSecret(false), 2000)
                        }}
                        className="rounded bg-amber-200 px-3 py-2 text-amber-900 hover:bg-amber-300"
                      >
                        {copiedSecret ? <Check className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                )}
              </div>
              <button
                onClick={() => setCreatedSecret(null)}
                className="mt-4 text-xs font-semibold text-amber-800 underline hover:text-amber-950"
              >
                ปิดข้อความเตือนนี้
              </button>
            </div>
          )}

          {/* Rotated Secret Alert */}
          {rotatedSecretData && (
            <div className="rounded-2xl border border-purple-300 bg-purple-50 p-5 shadow-sm">
              <h3 className="font-semibold text-purple-900">
                สลับ Client Secret ใหม่สำเร็จ!
              </h3>
              <p className="mt-1 text-xs text-purple-700">
                Secret เก่าถูกยกเลิกแล้ว กรุณาคัดลอก Secret ใหม่นี้ไปอัปเดตในระบบของแอปทันที
              </p>
              <div className="mt-3 space-y-2 text-xs">
                <div>
                  <span className="font-semibold text-purple-900">Client ID:</span>
                  <div className="mt-1 text-xs font-mono text-purple-950">{rotatedSecretData.clientId}</div>
                </div>
                <div>
                  <span className="font-semibold text-purple-900">New Client Secret:</span>
                  <div className="mt-1 flex items-center gap-2">
                    <input
                      readOnly
                      value={rotatedSecretData.clientSecret}
                      className="w-full rounded bg-white p-2 font-mono border border-purple-200 text-slate-800"
                    />
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(rotatedSecretData.clientSecret)
                        setCopiedRotatedSecret(true)
                        setTimeout(() => setCopiedRotatedSecret(false), 2000)
                      }}
                      className="rounded bg-purple-200 px-3 py-2 text-purple-900 hover:bg-purple-300"
                    >
                      {copiedRotatedSecret ? <Check className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setRotatedSecretData(null)}
                className="mt-4 text-xs font-semibold text-purple-800 underline hover:text-purple-950"
              >
                ปิดข้อความเตือนนี้
              </button>
            </div>
          )}

          {/* Add Form */}
          {showAddForm && (
            <form onSubmit={handleCreateClient} className="rounded-2xl bg-white p-6 shadow space-y-4">
              <h3 className="font-semibold text-slate-800">ลงทะเบียนเว็บภายนอก (เช่น app1, app2)</h3>
              <div>
                <label className="block text-xs font-medium text-slate-600">ชื่อแอป (App Name)</label>
                <input
                  type="text"
                  required
                  placeholder="เช่น App 1 หรือ Internal Portal"
                  value={clientName}
                  onChange={(e) => setClientName(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-300 p-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600">
                  Redirect URIs (1 บรรทัดต่อ 1 URL)
                </label>
                <textarea
                  required
                  rows={2}
                  placeholder="http://localhost:3000/callback"
                  value={redirectUris}
                  onChange={(e) => setRedirectUris(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-300 p-2 font-mono text-sm"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="is_conf"
                  checked={isConfidential}
                  onChange={(e) => setIsConfidential(e.target.checked)}
                  className="rounded border-slate-300 text-blue-600"
                />
                <label htmlFor="is_conf" className="text-xs text-slate-600">
                  Confidential Client (มี Server Backend เพื่อเก็บ Client Secret)
                </label>
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddForm(false)}
                  className="rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-600 hover:bg-slate-50"
                >
                  ยกเลิก
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
                >
                  สร้างแอป
                </button>
              </div>
            </form>
          )}

          {/* Edit Client Modal */}
          {editingClient && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4">
              <form
                onSubmit={handleSaveEditClient}
                className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl space-y-4"
              >
                <div className="flex items-center justify-between border-b pb-2">
                  <h3 className="font-semibold text-slate-800">แก้ไขข้อมูลแอป</h3>
                  <button
                    type="button"
                    onClick={() => setEditingClient(null)}
                    className="text-slate-400 hover:text-slate-600"
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600">ชื่อแอป</label>
                  <input
                    type="text"
                    required
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-slate-300 p-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600">
                    Redirect URIs (1 บรรทัดต่อ 1 URL)
                  </label>
                  <textarea
                    required
                    rows={3}
                    value={editRedirectUris}
                    onChange={(e) => setEditRedirectUris(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-slate-300 p-2 font-mono text-sm"
                  />
                </div>
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setEditingClient(null)}
                    className="rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-600 hover:bg-slate-50"
                  >
                    ยกเลิก
                  </button>
                  <button
                    type="submit"
                    disabled={savingClient}
                    className="rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-50"
                  >
                    {savingClient ? 'กำลังบันทึก...' : 'บันทึก'}
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* Invites Management Modal */}
          {inviteModalClient && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4">
              <div className="w-full max-w-xl rounded-2xl bg-white p-6 shadow-xl space-y-4 max-h-[90vh] flex flex-col">
                <div className="flex items-center justify-between border-b pb-3">
                  <div>
                    <h3 className="font-semibold text-slate-800">
                      จัดการคำเชิญ (Invites): {inviteModalClient.client_name}
                    </h3>
                    <p className="text-xs text-slate-500">
                      ผู้ใช้ที่ได้รับเชิญจะได้รับสิทธิ์เข้าใช้งานแอปนี้โดยอัตโนมัติเมื่อเข้าสู่ระบบครั้งแรก
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setInviteModalClient(null)}
                    className="text-slate-400 hover:text-slate-600"
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>

                {/* Add Invite Form */}
                <form onSubmit={handleAddInvite} className="flex gap-2 items-center bg-slate-50 p-3 rounded-xl border">
                  <input
                    type="email"
                    required
                    placeholder="อีเมลผู้ได้รับเชิญ (เช่น user@example.com)"
                    value={newInviteEmail}
                    onChange={(e) => setNewInviteEmail(e.target.value)}
                    className="flex-1 rounded-lg border border-slate-300 p-2 text-xs"
                  />
                  <select
                    value={newInviteRole}
                    onChange={(e) => setNewInviteRole(e.target.value as 'admin' | 'member' | 'viewer')}
                    className="rounded-lg border border-slate-300 bg-white p-2 text-xs font-medium"
                  >
                    <option value="member">Member</option>
                    <option value="admin">Admin</option>
                    <option value="viewer">Viewer</option>
                  </select>
                  <button
                    type="submit"
                    disabled={addingInvite}
                    className="inline-flex items-center gap-1 rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                  >
                    <UserPlus className="h-3.5 w-3.5" />
                    <span>{addingInvite ? 'กำลังเพิ่ม...' : 'เชิญ'}</span>
                  </button>
                </form>

                {/* Invites List */}
                <div className="flex-1 overflow-y-auto">
                  {invitesLoading ? (
                    <p className="p-6 text-center text-xs text-slate-500">กำลังโหลดรายการคำเชิญ...</p>
                  ) : invites.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-slate-300 p-8 text-center text-xs text-slate-500">
                      ยังไม่มีรายการคำเชิญที่รอดำเนินการ
                    </div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b bg-slate-50 text-slate-500">
                          <th className="p-2.5">อีเมล</th>
                          <th className="p-2.5">สิทธิ์เริ่มต้น</th>
                          <th className="p-2.5">วันที่เชิญ</th>
                          <th className="p-2.5 text-right">จัดการ</th>
                        </tr>
                      </thead>
                      <tbody>
                        {invites.map((inv) => (
                          <tr key={inv.id} className="border-b last:border-0 hover:bg-slate-50">
                            <td className="p-2.5 font-medium text-slate-800">{inv.email}</td>
                            <td className="p-2.5">
                              <span className="rounded bg-slate-100 px-2 py-0.5 text-[11px] font-semibold text-slate-700">
                                {inv.initial_role}
                              </span>
                            </td>
                            <td className="p-2.5 text-slate-500">
                              {new Date(inv.created_at).toLocaleString('th-TH')}
                            </td>
                            <td className="p-2.5 text-right">
                              <button
                                onClick={() => handleDeleteInvite(inv.id)}
                                className="rounded p-1 text-slate-400 hover:bg-red-50 hover:text-red-600"
                                title="ลบคำเชิญ"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>

                <div className="flex justify-end pt-2 border-t">
                  <button
                    type="button"
                    onClick={() => setInviteModalClient(null)}
                    className="rounded-lg border border-slate-300 px-4 py-1.5 text-xs text-slate-600 hover:bg-slate-50"
                  >
                    ปิด
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Attack Protection Modal (Auth0 Style) */}
          {attackModalClient && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4">
              <div className="w-full max-w-2xl rounded-2xl bg-white p-6 shadow-2xl space-y-6 max-h-[90vh] overflow-y-auto">
                <div className="flex items-start justify-between border-b pb-4">
                  <div>
                    <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2">
                      <ShieldAlert className="h-6 w-6 text-blue-600" />
                      Attack Protection
                    </h2>
                    <p className="mt-1 text-xs text-slate-500">
                      ระบบตรวจจับและป้องกันภัยคุกคามอัตโนมัติสำหรับแอป <span className="font-semibold text-slate-800">{attackModalClient.client_name}</span> (ID: <code className="font-mono text-slate-600">{attackModalClient.client_id}</code>)
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setAttackModalClient(null)}
                    className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>

                {/* 4 Protection Cards */}
                <div className="space-y-3">
                  {/* 1. Bot Detection */}
                  <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white p-4 hover:border-slate-300 transition shadow-xs">
                    <div className="flex items-start gap-4">
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-2.5 text-slate-700">
                        <Bot className="h-5 w-5" />
                      </div>
                      <div>
                        <div className="font-semibold text-sm text-slate-900">Bot Detection</div>
                        <p className="text-xs text-slate-500 max-w-md mt-0.5">
                          ตรวจจับสคริปต์อัตโนมัติและบอทในหน้า Authorize/Consent เพื่อป้องกันการยิงสิทธิ์อัตโนมัติ
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`text-xs font-medium flex items-center gap-1.5 ${attackConfig.bot_detection ? 'text-emerald-700 font-semibold' : 'text-slate-500'}`}>
                        <span className={`h-2 w-2 rounded-full ${attackConfig.bot_detection ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                        {attackConfig.bot_detection ? 'Enabled' : 'Disabled'}
                      </span>
                      <button
                        type="button"
                        disabled={savingAttackProtection}
                        onClick={() => handleToggleAttackProtection('bot_detection')}
                        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                          attackConfig.bot_detection ? 'bg-blue-600' : 'bg-slate-200'
                        }`}
                      >
                        <span
                          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                            attackConfig.bot_detection ? 'translate-x-5' : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </div>
                  </div>

                  {/* 2. Suspicious IP Throttling */}
                  <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white p-4 hover:border-slate-300 transition shadow-xs">
                    <div className="flex items-start gap-4">
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-2.5 text-slate-700">
                        <TrendingUp className="h-5 w-5" />
                      </div>
                      <div>
                        <div className="font-semibold text-sm text-slate-900">Suspicious IP Throttling</div>
                        <p className="text-xs text-slate-500 max-w-md mt-0.5">
                          จำกัดความเร็วและระงับการยิงคำขอที่ผิดปกติจาก IP ต้องสงสัย เพื่อป้องกันการโจมตี DDoS หรือ Token Flooding
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`text-xs font-medium flex items-center gap-1.5 ${attackConfig.suspicious_ip_throttling ? 'text-emerald-700 font-semibold' : 'text-slate-500'}`}>
                        <span className={`h-2 w-2 rounded-full ${attackConfig.suspicious_ip_throttling ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                        {attackConfig.suspicious_ip_throttling ? 'Enabled' : 'Disabled'}
                      </span>
                      <button
                        type="button"
                        disabled={savingAttackProtection}
                        onClick={() => handleToggleAttackProtection('suspicious_ip_throttling')}
                        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                          attackConfig.suspicious_ip_throttling ? 'bg-blue-600' : 'bg-slate-200'
                        }`}
                      >
                        <span
                          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                            attackConfig.suspicious_ip_throttling ? 'translate-x-5' : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </div>
                  </div>

                  {/* 3. Brute-force Protection */}
                  <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white p-4 hover:border-slate-300 transition shadow-xs">
                    <div className="flex items-start gap-4">
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-2.5 text-slate-700">
                        <Lock className="h-5 w-5" />
                      </div>
                      <div>
                        <div className="font-semibold text-sm text-slate-900">Brute-force Protection</div>
                        <p className="text-xs text-slate-500 max-w-md mt-0.5">
                          ป้องกันการเดารหัส Token/Code หรือ Secret โดยการล็อกชั่วคราว 15 นาทีเมื่อพบความล้มเหลวติดต่อกัน 5 ครั้ง
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`text-xs font-medium flex items-center gap-1.5 ${attackConfig.brute_force_protection ? 'text-emerald-700 font-semibold' : 'text-slate-500'}`}>
                        <span className={`h-2 w-2 rounded-full ${attackConfig.brute_force_protection ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                        {attackConfig.brute_force_protection ? 'Enabled' : 'Disabled'}
                      </span>
                      <button
                        type="button"
                        disabled={savingAttackProtection}
                        onClick={() => handleToggleAttackProtection('brute_force_protection')}
                        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                          attackConfig.brute_force_protection ? 'bg-blue-600' : 'bg-slate-200'
                        }`}
                      >
                        <span
                          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                            attackConfig.brute_force_protection ? 'translate-x-5' : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </div>
                  </div>

                  {/* 4. Suspicious Account Shield */}
                  <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white p-4 hover:border-slate-300 transition shadow-xs">
                    <div className="flex items-start gap-4">
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-2.5 text-slate-700">
                        <Shield className="h-5 w-5" />
                      </div>
                      <div>
                        <div className="font-semibold text-sm text-slate-900">Suspicious Account Shield</div>
                        <p className="text-xs text-slate-500 max-w-md mt-0.5">
                          ตรวจจับบัญชีที่มีพฤติกรรมเสี่ยง และบังคับยืนยันตัวตนใหม่ก่อนให้สิทธิ์เข้าถึงแอปนี้
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`text-xs font-medium flex items-center gap-1.5 ${attackConfig.suspicious_account_shield ? 'text-emerald-700 font-semibold' : 'text-slate-500'}`}>
                        <span className={`h-2 w-2 rounded-full ${attackConfig.suspicious_account_shield ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                        {attackConfig.suspicious_account_shield ? 'Enabled' : 'Disabled'}
                      </span>
                      <button
                        type="button"
                        disabled={savingAttackProtection}
                        onClick={() => handleToggleAttackProtection('suspicious_account_shield')}
                        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                          attackConfig.suspicious_account_shield ? 'bg-blue-600' : 'bg-slate-200'
                        }`}
                      >
                        <span
                          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                            attackConfig.suspicious_account_shield ? 'translate-x-5' : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end pt-2 border-t">
                  <button
                    type="button"
                    onClick={() => setAttackModalClient(null)}
                    className="rounded-lg bg-slate-900 px-5 py-2 text-xs font-medium text-white hover:bg-slate-800 transition shadow-sm"
                  >
                    เสร็จสิ้น
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Apps Table */}
          {clients && clients.length === 0 ? (
            <div className="rounded-2xl bg-white p-8 text-center text-slate-500 shadow">
              ยังไม่มีแอปที่ลงทะเบียนไว้ กดปุ่ม "ลงทะเบียนแอปใหม่" ด้านบนเพื่อเริ่มเชื่อมต่อ
            </div>
          ) : (
            <div className="overflow-hidden rounded-2xl bg-white shadow">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b bg-slate-50 text-slate-500 text-xs">
                    <th className="p-3">ชื่อแอป</th>
                    <th className="p-3">Client ID</th>
                    <th className="p-3">ประเภท</th>
                    <th className="p-3">โหมดการเข้าถึง</th>
                    <th className="p-3">สถานะแอป</th>
                    <th className="p-3">ผู้ใช้</th>
                    <th className="p-3 text-right">การจัดการ</th>
                  </tr>
                </thead>
                <tbody>
                  {clients?.map((c) => (
                    <tr key={c.client_id} className="border-b last:border-0 hover:bg-slate-50">
                      <td className="p-3">
                        <div className="font-semibold text-slate-800">{c.client_name}</div>
                        <div className="text-[11px] text-slate-400 truncate max-w-xs font-mono" title={c.redirect_uris.join(', ')}>
                          {c.redirect_uris[0]} {c.redirect_uris.length > 1 ? `(+${c.redirect_uris.length - 1})` : ''}
                        </div>
                      </td>
                      <td className="p-3 font-mono text-xs text-slate-600">
                        <div className="flex items-center gap-1">
                          <span className="truncate max-w-[130px]">{c.client_id}</span>
                          <button
                            onClick={() => navigator.clipboard.writeText(c.client_id)}
                            title="คัดลอก Client ID"
                            className="text-slate-400 hover:text-slate-700"
                          >
                            <Copy className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                      <td className="p-3 text-xs">
                        <span
                          className={`rounded-full px-2 py-0.5 font-medium ${
                            c.is_confidential
                              ? 'bg-blue-50 text-blue-700 border border-blue-200'
                              : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          }`}
                        >
                          {c.is_confidential ? 'Confidential' : 'Public (PKCE)'}
                        </span>
                      </td>

                      {/* Access Mode Toggle */}
                      <td className="p-3 text-xs">
                        <button
                          onClick={() => handleToggleAccessMode(c)}
                          title="คลิกเพื่อสลับโหมด Open / Invite Only"
                          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium border transition ${
                            c.access_mode === 'invite_only'
                              ? 'bg-amber-50 text-amber-700 border-amber-300 hover:bg-amber-100'
                              : 'bg-slate-50 text-slate-700 border-slate-300 hover:bg-slate-100'
                          }`}
                        >
                          <Mail className="h-3 w-3" />
                          <span>{c.access_mode === 'invite_only' ? 'Invite Only' : 'Open'}</span>
                        </button>
                      </td>

                      {/* Status Toggle (Active / Disabled) */}
                      <td className="p-3 text-xs">
                        <button
                          onClick={() => handleToggleClientActive(c)}
                          title="คลิกเพื่อเปิด/ปิดการทำงานของแอป"
                          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium border transition ${
                            c.is_active
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100'
                              : 'bg-rose-50 text-rose-700 border-rose-300 hover:bg-rose-100'
                          }`}
                        >
                          {c.is_active ? <CheckCircle2 className="h-3 w-3" /> : <Ban className="h-3 w-3" />}
                          <span>{c.is_active ? 'เปิดใช้งาน' : 'ระงับชั่วคราว'}</span>
                        </button>
                      </td>

                      {/* User Count */}
                      <td className="p-3">
                        <button
                          onClick={() => {
                            setSelectedClientId(c.client_id)
                            setTab('app_users')
                          }}
                          className="inline-flex items-center gap-1 rounded bg-slate-100 px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-blue-50 hover:text-blue-700"
                        >
                          <Users className="h-3 w-3" />
                          <span>{c.user_count || 0} คน</span>
                        </button>
                      </td>

                      {/* Actions */}
                      <td className="p-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {/* Attack Protection Button */}
                          <button
                            onClick={() => handleOpenAttackModal(c)}
                            title="ตั้งค่า Attack Protection (Bot, Brute-force, IP Throttle, Account Shield)"
                            className="rounded p-1.5 text-slate-500 hover:bg-emerald-50 hover:text-emerald-700"
                          >
                            <ShieldAlert className="h-4 w-4" />
                          </button>

                          {/* Manage Invites Button */}
                          <button
                            onClick={() => handleOpenInvitesModal(c)}
                            title="จัดการคำเชิญ (Invites)"
                            className="rounded p-1.5 text-slate-500 hover:bg-cyan-50 hover:text-cyan-700"
                          >
                            <Mail className="h-4 w-4" />
                          </button>

                          {/* Rotate Secret Button (Confidential only) */}
                          {c.is_confidential && (
                            <button
                              onClick={() => handleRotateSecret(c)}
                              title="สลับ Client Secret ใหม่ (Rotate Secret)"
                              className="rounded p-1.5 text-slate-500 hover:bg-purple-50 hover:text-purple-700"
                            >
                              <RefreshCw className="h-4 w-4" />
                            </button>
                          )}

                          {/* Edit Client */}
                          <button
                            onClick={() => handleOpenEditClient(c)}
                            title="แก้ไขชื่อและ Redirect URIs"
                            className="rounded p-1.5 text-slate-500 hover:bg-blue-50 hover:text-blue-700"
                          >
                            <Edit3 className="h-4 w-4" />
                          </button>

                          {/* Delete Client */}
                          <button
                            onClick={() => handleDeleteClient(c.client_id)}
                            className="rounded p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600"
                            title="ลบแอป"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Users by App */}
      {tab === 'app_users' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-2xl bg-white p-4 shadow">
            <div>
              <h2 className="text-base font-semibold text-slate-800">จัดการสิทธิ์ผู้ใช้รายแอปพลิเคชัน</h2>
              <p className="text-xs text-slate-500">เลือกแอปพลิเคชันเพื่อจัดการ Role และการเข้าถึงของผู้ใช้</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-600">เลือกแอป:</span>
              <select
                value={selectedClientId}
                onChange={(e) => setSelectedClientId(e.target.value)}
                className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-800"
              >
                {clients?.map((c) => (
                  <option key={c.client_id} value={c.client_id}>
                    {c.client_name} ({c.user_count || 0} ผู้ใช้)
                  </option>
                ))}
              </select>
            </div>
          </div>

          {!selectedClientId ? (
            <p className="p-6 text-center text-sm text-slate-500">กรุณาสร้างหรือเลือกแอปก่อน</p>
          ) : !appUsers || appUsers.length === 0 ? (
            <div className="rounded-2xl bg-white p-8 text-center text-slate-500 shadow">
              ยังไม่มีผู้ใช้ล็อกอินเข้าสู่แอปนี้ เมื่อผู้ใช้ยืนยันสิทธิ์เข้ามา รายชื่อจะปรากฏที่นี่โดยอัตโนมัติ
            </div>
          ) : (
            <div className="overflow-hidden rounded-2xl bg-white shadow">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b bg-slate-50 text-slate-500">
                    <th className="p-3">ผู้ใช้งาน</th>
                    <th className="p-3">Role ในแอป</th>
                    <th className="p-3">สถานะการเข้าถึง</th>
                    <th className="p-3">เข้าใช้ล่าสุด</th>
                    <th className="p-3 text-right">การจัดการ</th>
                  </tr>
                </thead>
                <tbody>
                  {appUsers.map((u) => (
                    <tr key={u.user_id} className="border-b last:border-0 hover:bg-slate-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          {u.picture ? (
                            <img
                              src={u.picture}
                              alt={u.name}
                              referrerPolicy="no-referrer"
                              className="h-8 w-8 rounded-full"
                            />
                          ) : (
                            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200 text-xs font-semibold">
                              {u.name.charAt(0)}
                            </div>
                          )}
                          <div>
                            <div className="font-semibold text-slate-900">{u.name}</div>
                            <div className="text-xs text-slate-500">{u.email}</div>
                          </div>
                        </div>
                      </td>

                      {/* Role Dropdown */}
                      <td className="p-3">
                        <select
                          value={u.role}
                          onChange={(e) => handleRoleChange(u.user_id, e.target.value)}
                          className={`rounded-lg border px-2 py-1 text-xs font-semibold ${
                            u.role === 'admin'
                              ? 'border-purple-300 bg-purple-50 text-purple-700'
                              : 'border-slate-300 bg-white text-slate-700'
                          }`}
                        >
                          <option value="member">Member</option>
                          <option value="admin">Admin</option>
                          <option value="viewer">Viewer</option>
                        </select>
                      </td>

                      {/* Status Badge */}
                      <td className="p-3">
                        <span
                          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ${
                            u.status === 'active'
                              ? 'bg-emerald-50 text-emerald-700'
                              : 'bg-red-50 text-red-700'
                          }`}
                        >
                          {u.status === 'active' ? (
                            <>
                              <CheckCircle2 className="h-3 w-3" /> ปกติ (Active)
                            </>
                          ) : (
                            <>
                              <Ban className="h-3 w-3" /> ถูกตัดสิทธิ์ (Revoked)
                            </>
                          )}
                        </span>
                      </td>

                      <td className="p-3 text-xs text-slate-500">
                        {new Date(u.last_accessed_at).toLocaleString('th-TH')}
                      </td>

                      {/* Action Button: Revoke or Activate */}
                      <td className="p-3 text-right">
                        {u.status === 'active' ? (
                          <button
                            onClick={() => handleStatusToggle(u.user_id, u.status)}
                            className="inline-flex items-center gap-1 rounded-lg border border-red-200 bg-red-50 px-2.5 py-1 text-xs font-medium text-red-700 hover:bg-red-100"
                          >
                            <Ban className="h-3 w-3" /> ตัดสิทธิ์
                          </button>
                        ) : (
                          <button
                            onClick={() => handleStatusToggle(u.user_id, u.status)}
                            className="inline-flex items-center gap-1 rounded-lg border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700 hover:bg-emerald-100"
                          >
                            <Check className="h-3 w-3" /> คืนสิทธิ์
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: All Users in System */}
      {tab === 'all_users' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-2xl bg-white p-4 shadow">
            <div>
              <h2 className="text-base font-semibold text-slate-800">ผู้ใช้ทั้งหมดในระบบ SSO</h2>
              <p className="text-xs text-slate-500">จัดการสิทธิ์ Admin, ตรวจสอบแอปที่เชื่อมต่อ, เตะออกจากระบบ, หรือระงับบัญชี</p>
            </div>
            <div className="relative w-full sm:w-64">
              <input
                type="text"
                placeholder="ค้นหาชื่อ หรือ อีเมล..."
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
                className="w-full rounded-lg border border-slate-300 py-1.5 pl-8 pr-3 text-xs"
              />
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
            </div>
          </div>

          {/* User Details Modal */}
          {(inspectingUser || inspectingLoading) && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4">
              <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-xl space-y-4 max-h-[90vh] overflow-y-auto">
                <div className="flex items-center justify-between border-b pb-3">
                  <h3 className="font-semibold text-slate-800">ข้อมูลผู้ใช้และการเข้าถึงแอป</h3>
                  <button
                    type="button"
                    onClick={() => setInspectingUser(null)}
                    className="text-slate-400 hover:text-slate-600"
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>

                {inspectingLoading || !inspectingUser ? (
                  <p className="p-6 text-center text-xs text-slate-500">กำลังโหลดข้อมูลผู้ใช้...</p>
                ) : (
                  <div className="space-y-4 text-xs">
                    {/* User Profile Summary */}
                    <div className="flex items-center gap-3 bg-slate-50 p-3 rounded-xl border">
                      {inspectingUser.user.picture ? (
                        <img
                          src={inspectingUser.user.picture}
                          alt={inspectingUser.user.name}
                          className="h-12 w-12 rounded-full"
                        />
                      ) : (
                        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-slate-200 text-sm font-bold">
                          {inspectingUser.user.name.charAt(0)}
                        </div>
                      )}
                      <div>
                        <div className="text-sm font-semibold text-slate-900">{inspectingUser.user.name}</div>
                        <div className="text-slate-500">{inspectingUser.user.email}</div>
                        <div className="mt-1 flex items-center gap-2">
                          <span
                            className={`rounded-full px-2 py-0.5 font-medium ${
                              inspectingUser.user.status === 'active'
                                ? 'bg-emerald-50 text-emerald-700'
                                : 'bg-rose-50 text-rose-700'
                            }`}
                          >
                            {inspectingUser.user.status === 'active' ? 'Active' : 'Suspended'}
                          </span>
                          {inspectingUser.user.is_super_admin ? (
                            <span className="rounded-full bg-purple-50 text-purple-700 px-2 py-0.5 font-medium">
                              Super Admin
                            </span>
                          ) : inspectingUser.user.is_admin ? (
                            <span className="rounded-full bg-blue-50 text-blue-700 px-2 py-0.5 font-medium">
                              Admin
                            </span>
                          ) : null}
                        </div>
                      </div>
                    </div>

                    {/* Stats */}
                    <div className="grid grid-cols-2 gap-2 text-center">
                      <div className="bg-slate-50 p-2.5 rounded-lg border">
                        <div className="text-base font-bold text-slate-800">{inspectingUser.active_sessions_count}</div>
                        <div className="text-[11px] text-slate-500">Active Web Sessions</div>
                      </div>
                      <div className="bg-slate-50 p-2.5 rounded-lg border">
                        <div className="text-base font-bold text-slate-800">{inspectingUser.active_oauth_tokens_count}</div>
                        <div className="text-[11px] text-slate-500">Active OAuth Tokens</div>
                      </div>
                    </div>

                    {/* Apps Connected */}
                    <div>
                      <h4 className="font-semibold text-slate-700 mb-2">แอปที่ให้สิทธิ์เข้าถึง ({inspectingUser.apps.length})</h4>
                      {inspectingUser.apps.length === 0 ? (
                        <p className="text-slate-400 italic">ยังไม่เคยเข้าสู่ระบบผ่านแอปใด</p>
                      ) : (
                        <div className="space-y-1.5">
                          {inspectingUser.apps.map((app) => (
                            <div
                              key={app.client_id}
                              className="flex items-center justify-between p-2 rounded-lg bg-slate-50 border text-slate-700"
                            >
                              <div>
                                <span className="font-semibold text-slate-800">{app.client_name}</span>
                                <span className="ml-2 font-mono text-[10px] text-slate-400">({app.client_id})</span>
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-medium">
                                  {app.role}
                                </span>
                                <span
                                  className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                                    app.status === 'active' ? 'text-emerald-700 bg-emerald-50' : 'text-red-700 bg-red-50'
                                  }`}
                                >
                                  {app.status}
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="flex justify-end pt-2 border-t">
                  <button
                    type="button"
                    onClick={() => setInspectingUser(null)}
                    className="rounded-lg border border-slate-300 px-4 py-1.5 text-xs text-slate-600 hover:bg-slate-50"
                  >
                    ปิด
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Users Table */}
          <div className="overflow-hidden rounded-2xl bg-white shadow">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b bg-slate-50 text-slate-500 text-xs">
                  <th className="p-3">ผู้ใช้งาน</th>
                  <th className="p-3">สิทธิ์ในระบบ SSO</th>
                  <th className="p-3">สถานะบัญชี</th>
                  <th className="p-3">วันที่สร้าง / ล็อกอินล่าสุด</th>
                  <th className="p-3 text-right">การจัดการ</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers?.map((u) => {
                  const isSelf = currentUser?.id === u.id
                  return (
                    <tr key={u.id} className="border-b last:border-0 hover:bg-slate-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          {u.picture ? (
                            <img
                              src={u.picture}
                              alt={u.name}
                              referrerPolicy="no-referrer"
                              className="h-8 w-8 rounded-full"
                            />
                          ) : (
                            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200 text-xs font-semibold">
                              {u.name.charAt(0)}
                            </div>
                          )}
                          <div>
                            <div className="font-semibold text-slate-900 flex items-center gap-1.5">
                              <span>{u.name}</span>
                              {isSelf && (
                                <span className="rounded bg-blue-100 text-blue-700 text-[10px] px-1.5 py-0.2 font-medium">
                                  คุณ
                                </span>
                              )}
                            </div>
                            <div className="text-xs text-slate-500">{u.email}</div>
                          </div>
                        </div>
                      </td>

                      {/* System Role Badge & Toggle */}
                      <td className="p-3 text-xs">
                        {u.is_super_admin ? (
                          <span
                            title="Super Admin จากตัวแปรระบบ ADMIN_EMAILS (ไม่สามารถแก้ไขได้)"
                            className="inline-flex items-center gap-1 rounded-full bg-purple-50 text-purple-700 border border-purple-200 px-2.5 py-0.5 font-semibold"
                          >
                            <ShieldCheck className="h-3 w-3" /> Super Admin
                          </span>
                        ) : (
                          <button
                            onClick={() => handleToggleAdminStatus(u)}
                            disabled={isSelf}
                            title={isSelf ? 'ไม่สามารถถอดสิทธิ์ Admin ของตนเองได้' : 'คลิกเพื่อสลับสิทธิ์ Admin ในฐานข้อมูล'}
                            className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium border transition disabled:opacity-60 disabled:cursor-not-allowed ${
                              u.is_admin
                                ? 'bg-blue-50 text-blue-700 border-blue-300 hover:bg-blue-100'
                                : 'bg-slate-50 text-slate-600 border-slate-300 hover:bg-slate-100'
                            }`}
                          >
                            <Shield className="h-3 w-3" />
                            <span>{u.is_admin ? 'Admin' : 'User (กดเพื่อตั้ง Admin)'}</span>
                          </button>
                        )}
                      </td>

                      {/* Account Status Badge */}
                      <td className="p-3 text-xs">
                        <span
                          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 font-medium ${
                            u.status === 'active'
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                              : 'bg-rose-50 text-rose-700 border border-rose-200'
                          }`}
                        >
                          {u.status === 'active' ? (
                            <>
                              <CheckCircle2 className="h-3 w-3" /> ใช้งานปกติ
                            </>
                          ) : (
                            <>
                              <Ban className="h-3 w-3" /> ระงับบัญชี (Suspended)
                            </>
                          )}
                        </span>
                      </td>

                      {/* Dates */}
                      <td className="p-3 text-xs text-slate-500">
                        <div>สร้าง: {new Date(u.created_at).toLocaleDateString('th-TH')}</div>
                        <div className="text-[11px] text-slate-400">
                          ล่าสุด: {new Date(u.last_login_at).toLocaleString('th-TH')}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="p-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {/* Inspect User Details */}
                          <button
                            onClick={() => handleInspectUser(u.id)}
                            title="ดูรายละเอียดการเข้าถึงแอปและ Session"
                            className="rounded p-1.5 text-slate-500 hover:bg-blue-50 hover:text-blue-700"
                          >
                            <Eye className="h-4 w-4" />
                          </button>

                          {/* Force Logout Everywhere */}
                          <button
                            onClick={() => handleForceLogoutUser(u)}
                            title="เตะออกจากระบบทุกอุปกรณ์ (Force Logout)"
                            className="rounded p-1.5 text-slate-500 hover:bg-amber-50 hover:text-amber-700"
                          >
                            <LogOut className="h-4 w-4" />
                          </button>

                          {/* Suspend / Unsuspend */}
                          {!u.is_super_admin && !isSelf && (
                            <button
                              onClick={() => handleToggleSuspendUser(u)}
                              title={u.status === 'active' ? 'ระงับบัญชี (Suspend)' : 'ปลดการระงับ (Unsuspend)'}
                              className={`rounded p-1.5 ${
                                u.status === 'active'
                                  ? 'text-slate-400 hover:bg-rose-50 hover:text-rose-600'
                                  : 'text-rose-600 hover:bg-emerald-50 hover:text-emerald-700'
                              }`}
                            >
                              {u.status === 'active' ? <Lock className="h-4 w-4" /> : <Unlock className="h-4 w-4" />}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: Audit Logs */}
      {tab === 'audit_logs' && (
        <div className="space-y-4">
          {/* Filter Toolbar */}
          <div className="rounded-2xl bg-white p-4 shadow space-y-3">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold text-slate-800">ประวัติและบันทึกกิจกรรม (Audit Trail)</h2>
                <p className="text-xs text-slate-500">ค้นหา ตรวจสอบ และส่งออกประวัติกิจกรรมด้านความปลอดภัยทั้งหมดในระบบ</p>
              </div>

              {/* Export Buttons */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleExport('csv')}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
                >
                  <FileSpreadsheet className="h-3.5 w-3.5 text-emerald-600" />
                  <span>Export CSV</span>
                </button>
                <button
                  onClick={() => handleExport('json')}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
                >
                  <Download className="h-3.5 w-3.5 text-blue-600" />
                  <span>Export JSON</span>
                </button>
              </div>
            </div>

            {/* Search and Filters */}
            <form onSubmit={handleAuditSearchSubmit} className="grid gap-2 sm:grid-cols-4">
              <div className="relative sm:col-span-2">
                <input
                  type="text"
                  placeholder="พิมพ์ค้นหาอีเมล, ชื่อแอป, หรือรายละเอียด..."
                  value={auditSearch}
                  onChange={(e) => setAuditSearch(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 py-1.5 pl-8 pr-3 text-xs"
                />
                <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
              </div>

              <div>
                <select
                  value={auditEventType}
                  onChange={(e) => {
                    setAuditEventType(e.target.value)
                    setAuditOffset(0)
                  }}
                  className="w-full rounded-lg border border-slate-300 bg-white py-1.5 px-2.5 text-xs font-medium text-slate-700"
                >
                  <option value="">ทุกประเภทกิจกรรม (All Events)</option>
                  <option value="LOGIN">LOGIN (เข้าสู่ระบบ)</option>
                  <option value="LOGOUT">LOGOUT (ออกจากระบบ)</option>
                  <option value="FORCE_LOGOUT">FORCE_LOGOUT (บังคับออกจากระบบ)</option>
                  <option value="OAUTH_AUTHORIZE">OAUTH_AUTHORIZE (ให้สิทธิ์แอป)</option>
                  <option value="OAUTH_TOKEN">OAUTH_TOKEN (ออก Access Token)</option>
                  <option value="OAUTH_TOKEN_REFRESH">OAUTH_TOKEN_REFRESH (หมุนเวียน Refresh Token)</option>
                  <option value="OAUTH_TOKEN_REVOKE">OAUTH_TOKEN_REVOKE (เพิกถอน Token)</option>
                  <option value="REFRESH_TOKEN_REUSE_DETECTED">REFRESH_TOKEN_REUSE_DETECTED (ตรวจพบการใช้ซ้ำ)</option>
                  <option value="ROLE_UPDATED">ROLE_UPDATED (เปลี่ยนสิทธิ์ Role)</option>
                  <option value="STATUS_UPDATED">STATUS_UPDATED (ตัดสิทธิ์/คืนสิทธิ์ในแอป)</option>
                  <option value="USER_SUSPENDED">USER_SUSPENDED (ระงับบัญชีผู้ใช้)</option>
                  <option value="USER_UNSUSPENDED">USER_UNSUSPENDED (ปลดการระงับบัญชี)</option>
                  <option value="ADMIN_GRANTED">ADMIN_GRANTED (แต่งตั้ง Admin)</option>
                  <option value="ADMIN_REVOKED">ADMIN_REVOKED (ถอดสิทธิ์ Admin)</option>
                  <option value="CLIENT_CREATED">CLIENT_CREATED (สร้างแอปใหม่)</option>
                  <option value="CLIENT_UPDATED">CLIENT_UPDATED (แก้ไขข้อมูลแอป)</option>
                  <option value="CLIENT_SECRET_ROTATED">CLIENT_SECRET_ROTATED (สลับ Secret)</option>
                  <option value="CLIENT_DELETED">CLIENT_DELETED (ลบแอป)</option>
                  <option value="INVITE_CREATED">INVITE_CREATED (สร้างคำเชิญ)</option>
                  <option value="INVITE_DELETED">INVITE_DELETED (ลบคำเชิญ)</option>
                  <option value="ACCOUNT_DELETED">ACCOUNT_DELETED (ลบบัญชี)</option>
                </select>
              </div>

              <div>
                <select
                  value={auditClientId}
                  onChange={(e) => {
                    setAuditClientId(e.target.value)
                    setAuditOffset(0)
                  }}
                  className="w-full rounded-lg border border-slate-300 bg-white py-1.5 px-2.5 text-xs font-medium text-slate-700"
                >
                  <option value="">ทุกแอปพลิเคชัน (All Apps)</option>
                  {clients?.map((c) => (
                    <option key={c.client_id} value={c.client_id}>
                      {c.client_name}
                    </option>
                  ))}
                </select>
              </div>
            </form>
          </div>

          {/* Audit Logs Table */}
          {auditLoading ? (
            <div className="flex items-center justify-center rounded-2xl bg-white p-12 text-slate-500 shadow">
              <RefreshCw className="mr-2 h-4 w-4 animate-spin text-blue-600" />
              <span className="text-sm">กำลังโหลดข้อมูลบันทึกกิจกรรม...</span>
            </div>
          ) : auditLogs.length === 0 ? (
            <div className="rounded-2xl bg-white p-8 text-center text-slate-500 shadow">
              ไม่พบบันทึกกิจกรรมตามเงื่อนไขที่ค้นหา
            </div>
          ) : (
            <div className="overflow-hidden rounded-2xl bg-white shadow">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b bg-slate-50 text-slate-500">
                    <th className="p-3">วันและเวลา (UTC)</th>
                    <th className="p-3">กิจกรรม</th>
                    <th className="p-3">ผู้ใช้งาน</th>
                    <th className="p-3">แอปเป้าหมาย</th>
                    <th className="p-3">ผู้ดำเนินการ</th>
                    <th className="p-3">รายละเอียด (Details)</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="border-b last:border-0 hover:bg-slate-50">
                      <td className="p-3 font-mono text-slate-500 whitespace-nowrap">
                        {new Date(log.created_at).toLocaleString('th-TH')}
                      </td>
                      <td className="p-3">
                        <span
                          className={`inline-block rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold ${getEventBadge(
                            log.event_type
                          )}`}
                        >
                          {log.event_type}
                        </span>
                      </td>
                      <td className="p-3 font-medium text-slate-800">
                        {log.user_email || <span className="text-slate-400">-</span>}
                      </td>
                      <td className="p-3 text-slate-600">
                        {log.client_name ? (
                          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-slate-700">
                            {log.client_name}
                          </span>
                        ) : (
                          <span className="text-slate-400">-</span>
                        )}
                      </td>
                      <td className="p-3 text-slate-600 truncate max-w-[140px]" title={log.action_by}>
                        {log.action_by}
                      </td>
                      <td className="p-3 font-mono text-[11px] text-slate-600 max-w-xs break-all">
                        {log.details ? (
                          <span className="bg-slate-50 p-1 rounded border border-slate-100">
                            {log.details}
                          </span>
                        ) : (
                          <span className="text-slate-400">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {/* Pagination Footer */}
              <div className="flex items-center justify-between border-t border-slate-100 bg-slate-50 px-4 py-2 text-xs text-slate-600">
                <span>
                  แสดง {auditLogs.length} จากทั้งหมด <strong>{auditTotal}</strong> รายการ
                </span>
                <div className="flex gap-1">
                  <button
                    disabled={auditOffset === 0}
                    onClick={() => setAuditOffset(Math.max(0, auditOffset - AUDIT_LIMIT))}
                    className="rounded border border-slate-300 bg-white px-2.5 py-1 font-medium hover:bg-slate-100 disabled:opacity-40"
                  >
                    ก่อนหน้า
                  </button>
                  <button
                    disabled={auditOffset + AUDIT_LIMIT >= auditTotal}
                    onClick={() => setAuditOffset(auditOffset + AUDIT_LIMIT)}
                    className="rounded border border-slate-300 bg-white px-2.5 py-1 font-medium hover:bg-slate-100 disabled:opacity-40"
                  >
                    ถัดไป
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
