import { useEffect, useState } from 'react'
import {
  Activity,
  ArrowRight,
  BadgeCheck,
  CheckCircle2,
  FileText,
  Globe,
  KeyRound,
  LogOut,
  Mail,
  RefreshCw,
  Shield,
  ShieldCheck,
  Unlink,
  UserCheck,
  Users,
} from 'lucide-react'
import { api } from '../api'
import type { AdminDashboardStats, UserDashboardData, UserProfile } from '../types/auth'

interface Props {
  profile: UserProfile
  onSignOut: () => void
  onNavigateAdminTab: (tab: 'apps' | 'app_users' | 'all_users' | 'audit_logs') => void
}

export default function DashboardView({ profile, onSignOut, onNavigateAdminTab }: Props) {
  const [adminStats, setAdminStats] = useState<AdminDashboardStats | null>(null)
  const [userData, setUserData] = useState<UserDashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [disconnectingId, setDisconnectingId] = useState<string | null>(null)

  const loadData = () => {
    setLoading(true)
    const promises: Promise<unknown>[] = [api.userDashboard().then(setUserData)]
    if (profile.is_admin) {
      promises.push(api.adminDashboardStats().then(setAdminStats))
    }
    Promise.all(promises)
      .catch(() => undefined)
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [profile.is_admin])

  const handleDisconnect = async (clientId: string, clientName: string) => {
    if (!confirm(`ยืนยันการตัดการเชื่อมต่อแอป "${clientName}" หรือไม่? Access Token และ Refresh Token ของคุณสำหรับแอปนี้จะถูกเพิกถอนทันที`)) {
      return
    }
    setDisconnectingId(clientId)
    try {
      await api.userDisconnectApp(clientId)
      loadData()
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'ตัดการเชื่อมต่อไม่สำเร็จ')
    } finally {
      setDisconnectingId(null)
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
      case 'USER_APP_DISCONNECTED':
        return 'bg-rose-50 text-rose-700 border-rose-200'
      case 'ROLE_UPDATED':
        return 'bg-amber-50 text-amber-700 border-amber-200'
      default:
        return 'bg-slate-50 text-slate-700 border-slate-200'
    }
  }

  return (
    <div className="space-y-6">
      {/* 1. Header & Profile Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 rounded-2xl bg-white p-6 shadow-sm border border-slate-100">
        <div className="flex items-center gap-4">
          {profile.picture ? (
            <img
              src={profile.picture}
              alt={profile.name}
              referrerPolicy="no-referrer"
              className="h-16 w-16 rounded-full ring-2 ring-blue-100"
            />
          ) : (
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-blue-100 text-xl font-bold text-blue-700">
              {profile.name.charAt(0)}
            </div>
          )}
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-slate-900">{profile.name}</h1>
              <BadgeCheck className="h-5 w-5 text-blue-600" />
            </div>
            <p className="flex items-center gap-1.5 text-xs text-slate-500 mt-0.5">
              <Mail className="h-3.5 w-3.5" /> {profile.email}
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              {profile.is_super_admin ? (
                <span className="inline-flex items-center gap-1 rounded-full bg-purple-50 text-purple-700 border border-purple-200 px-2.5 py-0.5 text-xs font-semibold">
                  <ShieldCheck className="h-3.5 w-3.5" /> Super Admin
                </span>
              ) : profile.is_admin ? (
                <span className="inline-flex items-center gap-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200 px-2.5 py-0.5 text-xs font-semibold">
                  <Shield className="h-3.5 w-3.5" /> Admin
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-0.5 text-xs font-medium">
                  สมาชิกทั่วไป
                </span>
              )}

              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 px-2.5 py-0.5 text-xs font-medium">
                <CheckCircle2 className="h-3 w-3" /> บัญชีปกติ (Active)
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start md:self-center">
          <button
            onClick={onSignOut}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 shadow-sm"
          >
            <LogOut className="h-3.5 w-3.5" /> ออกจากระบบ
          </button>
        </div>
      </div>

      {/* 2. ADMIN DASHBOARD SECTION */}
      {profile.is_admin && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-blue-600" />
                ภาพรวมระบบและความปลอดภัย (Admin System Overview)
              </h2>
              <p className="text-xs text-slate-500">สถิติและกิจกรรมความปลอดภัยทั้งหมดในระบบ SSO</p>
            </div>
            <button
              onClick={loadData}
              title="รีเฟรชข้อมูล"
              className="rounded-lg border border-slate-200 bg-white p-2 text-slate-600 hover:bg-slate-50 shadow-sm"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin text-blue-600' : ''}`} />
            </button>
          </div>

          {/* 4 Stat Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {/* Card 1: Apps */}
            <div
              onClick={() => onNavigateAdminTab('apps')}
              className="cursor-pointer rounded-2xl bg-white p-4 shadow-sm border border-slate-100 hover:border-blue-300 hover:shadow transition group"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">แอปพลิเคชัน OAuth</span>
                <div className="rounded-xl bg-blue-50 p-2 text-blue-600 group-hover:bg-blue-600 group-hover:text-white transition">
                  <KeyRound className="h-4 w-4" />
                </div>
              </div>
              <div className="mt-2 text-2xl font-bold text-slate-900">
                {adminStats ? adminStats.total_apps : '...'}
              </div>
              <div className="mt-1 text-[11px] text-emerald-600 font-medium">
                เปิดใช้งาน {adminStats?.active_apps || 0} แอป
              </div>
            </div>

            {/* Card 2: Users */}
            <div
              onClick={() => onNavigateAdminTab('all_users')}
              className="cursor-pointer rounded-2xl bg-white p-4 shadow-sm border border-slate-100 hover:border-purple-300 hover:shadow transition group"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">ผู้ใช้ทั้งหมดในระบบ</span>
                <div className="rounded-xl bg-purple-50 p-2 text-purple-600 group-hover:bg-purple-600 group-hover:text-white transition">
                  <Users className="h-4 w-4" />
                </div>
              </div>
              <div className="mt-2 text-2xl font-bold text-slate-900">
                {adminStats ? adminStats.total_users : '...'}
              </div>
              <div className="mt-1 text-[11px] text-purple-600 font-medium">
                จัดการสิทธิ์และบัญชีผู้ใช้
              </div>
            </div>

            {/* Card 3: Active Sessions */}
            <div className="rounded-2xl bg-white p-4 shadow-sm border border-slate-100">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">Active Web Sessions</span>
                <div className="rounded-xl bg-emerald-50 p-2 text-emerald-600">
                  <Globe className="h-4 w-4" />
                </div>
              </div>
              <div className="mt-2 text-2xl font-bold text-slate-900">
                {adminStats ? adminStats.active_sessions : '...'}
              </div>
              <div className="mt-1 text-[11px] text-slate-400">
                เซสชันที่ยังไม่หมดอายุ
              </div>
            </div>

            {/* Card 4: Active OAuth Tokens */}
            <div className="rounded-2xl bg-white p-4 shadow-sm border border-slate-100">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">Active OAuth Tokens</span>
                <div className="rounded-xl bg-indigo-50 p-2 text-indigo-600">
                  <Activity className="h-4 w-4" />
                </div>
              </div>
              <div className="mt-2 text-2xl font-bold text-slate-900">
                {adminStats ? adminStats.active_tokens : '...'}
              </div>
              <div className="mt-1 text-[11px] text-slate-400">
                โทเค็นที่แอปภายนอกถืออยู่
              </div>
            </div>
          </div>

          {/* Quick Actions Bar */}
          <div className="flex flex-wrap items-center gap-2 rounded-2xl bg-slate-50 p-3 border border-slate-200">
            <span className="text-xs font-semibold text-slate-700 mr-1">ทางลัดจัดการ:</span>
            <button
              onClick={() => onNavigateAdminTab('apps')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-white border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-blue-50 hover:text-blue-700 hover:border-blue-300 shadow-sm transition"
            >
              <KeyRound className="h-3.5 w-3.5" /> จัดการแอป OAuth
            </button>
            <button
              onClick={() => onNavigateAdminTab('app_users')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-white border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-blue-50 hover:text-blue-700 hover:border-blue-300 shadow-sm transition"
            >
              <UserCheck className="h-3.5 w-3.5" /> จัดการสิทธิ์รายแอป
            </button>
            <button
              onClick={() => onNavigateAdminTab('all_users')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-white border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-blue-50 hover:text-blue-700 hover:border-blue-300 shadow-sm transition"
            >
              <Users className="h-3.5 w-3.5" /> จัดการผู้ใช้ทั้งหมด
            </button>
            <button
              onClick={() => onNavigateAdminTab('audit_logs')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-white border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-blue-50 hover:text-blue-700 hover:border-blue-300 shadow-sm transition"
            >
              <FileText className="h-3.5 w-3.5" /> บันทึกกิจกรรม & Export
            </button>
          </div>

          {/* Recent Security Activity Table */}
          {adminStats && adminStats.recent_logs.length > 0 && (
            <div className="overflow-hidden rounded-2xl bg-white shadow-sm border border-slate-100">
              <div className="flex items-center justify-between border-b bg-slate-50 px-4 py-3">
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  กิจกรรมความปลอดภัยล่าสุด (Recent Security Activity)
                </h3>
                <button
                  onClick={() => onNavigateAdminTab('audit_logs')}
                  className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800"
                >
                  <span>ดูทั้งหมดใน Audit Logs</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b bg-slate-50/50 text-slate-500">
                    <th className="p-3">เวลา</th>
                    <th className="p-3">กิจกรรม</th>
                    <th className="p-3">ผู้ใช้</th>
                    <th className="p-3">แอปเป้าหมาย</th>
                    <th className="p-3">ผู้ดำเนินการ</th>
                  </tr>
                </thead>
                <tbody>
                  {adminStats.recent_logs.map((log) => (
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
                        {log.user_email || '-'}
                      </td>
                      <td className="p-3 text-slate-600">
                        {log.client_name ? (
                          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-slate-700">
                            {log.client_name}
                          </span>
                        ) : (
                          '-'
                        )}
                      </td>
                      <td className="p-3 text-slate-500 truncate max-w-[140px]" title={log.action_by}>
                        {log.action_by}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* 3. USER PORTAL: CONNECTED APPS SECTION */}
      <div className="space-y-4">
        <div>
          <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-indigo-600" />
            แอปพลิเคชันที่เชื่อมต่อกับบัญชีของคุณ (Connected Applications)
          </h2>
          <p className="text-xs text-slate-500">
            รายการเว็บหรือแอปพลิเคชันภายนอกที่คุณเคยอนุญาตให้เข้าถึงข้อมูลยืนยันตัวตน SSO
          </p>
        </div>

        {userData?.apps && userData.apps.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-200 bg-white p-8 text-center text-slate-500 shadow-sm">
            <Unlink className="mx-auto h-8 w-8 text-slate-300 mb-2" />
            <p className="text-sm font-medium text-slate-700">ยังไม่มีแอปภายนอกที่เชื่อมต่อ</p>
            <p className="mt-1 text-xs text-slate-400">
              เมื่อคุณล็อกอินเข้าสู่เว็บอย่าง app1 หรือ app2 ระบบจะแสดงรายการแอปที่นี่โดยอัตโนมัติ
            </p>
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {userData?.apps.map((app) => (
              <div
                key={app.client_id}
                className="flex flex-col justify-between rounded-2xl bg-white p-5 shadow-sm border border-slate-100 hover:shadow-md transition"
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h3 className="font-semibold text-slate-900 text-sm">{app.client_name}</h3>
                      <p className="font-mono text-[11px] text-slate-400 truncate max-w-[200px]">
                        {app.client_id}
                      </p>
                    </div>
                    <span
                      className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
                        app.status === 'active'
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          : 'bg-red-50 text-red-700 border border-red-200'
                      }`}
                    >
                      {app.status}
                    </span>
                  </div>

                  <div className="mt-3 space-y-1 text-xs text-slate-600">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">สิทธิ์ในแอป (Role):</span>
                      <span className="font-semibold text-slate-700 rounded bg-slate-100 px-2 py-0.5 text-[11px]">
                        {app.role}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">เข้าใช้งานล่าสุด:</span>
                      <span className="text-slate-600">
                        {new Date(app.last_accessed_at).toLocaleString('th-TH')}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-100 flex justify-end">
                  <button
                    onClick={() => handleDisconnect(app.client_id, app.client_name)}
                    disabled={disconnectingId === app.client_id}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs font-medium text-red-600 hover:bg-red-100 disabled:opacity-50 transition"
                  >
                    <Unlink className="h-3.5 w-3.5" />
                    <span>{disconnectingId === app.client_id ? 'กำลังยกเลิก...' : 'ตัดการเชื่อมต่อแอป'}</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4. USER PORTAL: RECENT MY ACTIVITY */}
      {userData?.recent_activity && userData.recent_activity.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-slate-800 flex items-center gap-1.5">
            <Activity className="h-4 w-4 text-slate-500" />
            ประวัติกิจกรรมล่าสุดของบัญชีคุณ (Recent Account Activity)
          </h2>
          <div className="overflow-hidden rounded-2xl bg-white shadow-sm border border-slate-100">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b bg-slate-50 text-slate-500">
                  <th className="p-3">วันและเวลา</th>
                  <th className="p-3">กิจกรรม</th>
                  <th className="p-3">แอปพลิเคชัน</th>
                  <th className="p-3">รายละเอียด</th>
                </tr>
              </thead>
              <tbody>
                {userData.recent_activity.map((act) => (
                  <tr key={act.id} className="border-b last:border-0 hover:bg-slate-50">
                    <td className="p-3 font-mono text-slate-500 whitespace-nowrap">
                      {new Date(act.created_at).toLocaleString('th-TH')}
                    </td>
                    <td className="p-3">
                      <span
                        className={`inline-block rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold ${getEventBadge(
                          act.event_type
                        )}`}
                      >
                        {act.event_type}
                      </span>
                    </td>
                    <td className="p-3 text-slate-700 font-medium">
                      {act.client_name || '-'}
                    </td>
                    <td className="p-3 text-slate-500 font-mono text-[11px]">
                      {act.details || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
