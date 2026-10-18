import { useEffect, useState } from 'react'
import {
  Activity,
  FileText,
  Globe,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  UserCheck,
  Users,
} from 'lucide-react'
import { api } from '../api'
import type { AdminDashboardStats, UserProfile } from '../types/auth'

interface Props {
  profile: UserProfile
  onSignOut: () => void
  onNavigateAdminTab: (tab: 'apps' | 'app_users' | 'all_users' | 'audit_logs') => void
}

export default function DashboardView({ profile, onNavigateAdminTab }: Props) {
  const [adminStats, setAdminStats] = useState<AdminDashboardStats | null>(null)
  const [loading, setLoading] = useState(true)

  const loadData = () => {
    setLoading(true)
    if (profile.is_admin) {
      api
        .adminDashboardStats()
        .then(setAdminStats)
        .catch(() => undefined)
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [profile.is_admin])

  if (!profile.is_admin) {
    return (
      <div className="rounded-2xl bg-white p-8 text-center shadow-sm border border-slate-100">
        <h2 className="text-lg font-bold text-slate-800">เข้าสู่ระบบสำเร็จ</h2>
        <p className="mt-1 text-sm text-slate-500">
          คุณเข้าสู่ระบบในฐานะสมาชิกทั่วไป ({profile.email})
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header & Refresh */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-indigo-600" />
            ภาพรวมระบบและความปลอดภัย (Admin System Overview)
          </h2>
          <p className="text-xs text-slate-500">สถิติและกิจกรรมความปลอดภัยทั้งหมดในระบบ SSO</p>
        </div>
        <button
          onClick={loadData}
          title="รีเฟรชข้อมูล"
          className="rounded-lg border border-slate-200 bg-white p-2 text-slate-600 hover:bg-slate-50 shadow-sm transition"
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
          <div className="mt-1 text-[11px] text-slate-400">เซสชันที่ยังไม่หมดอายุ</div>
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
          <div className="mt-1 text-[11px] text-slate-400">โทเค็นที่แอปภายนอกถืออยู่</div>
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
    </div>
  )
}
