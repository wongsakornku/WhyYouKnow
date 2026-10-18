import { BadgeCheck, LogOut, Mail, ShieldCheck, Trash2 } from 'lucide-react'
import type { UserProfile } from '../types/auth'

interface Props {
  profile: UserProfile
  onSignOut: () => void
  onDelete: () => void
  onGoAdmin?: () => void
}

export default function ProfileCard({ profile, onSignOut, onDelete, onGoAdmin }: Props) {
  return (
    <div className="mx-auto max-w-md rounded-2xl bg-white p-8 text-center shadow">
      {profile.picture ? (
        <img
          src={profile.picture}
          alt={profile.name}
          referrerPolicy="no-referrer"
          className="mx-auto h-24 w-24 rounded-full ring-4 ring-blue-50"
        />
      ) : (
        <div className="mx-auto flex h-24 w-24 items-center justify-center rounded-full bg-blue-100 text-2xl font-bold text-blue-700">
          {profile.name.charAt(0)}
        </div>
      )}

      <h2 className="mt-4 flex items-center justify-center gap-1.5 text-xl font-bold text-slate-900">
        {profile.name}
        <BadgeCheck className="h-5 w-5 text-blue-600" />
      </h2>

      <p className="mt-1 flex items-center justify-center gap-1 text-sm text-slate-500">
        <Mail className="h-4 w-4" /> {profile.email}
      </p>

      {profile.is_admin ? (
        <div className="mt-4 rounded-xl border border-purple-200 bg-purple-50 p-3 text-xs text-purple-800">
          <p className="font-semibold flex items-center justify-center gap-1">
            <ShieldCheck className="h-4 w-4" /> บัญชีระดับผู้ดูแลระบบ (Admin)
          </p>
          <button
            onClick={onGoAdmin}
            className="mt-2 w-full rounded-lg bg-purple-700 py-1.5 font-medium text-white shadow-sm hover:bg-purple-800"
          >
            เปิดแผงควบคุมระบบ (Admin Dashboard)
          </button>
        </div>
      ) : (
        <div className="mt-4 rounded-xl border border-slate-100 bg-slate-50 p-3 text-xs text-slate-600">
          บัญชีของคุณพร้อมสำหรับการยืนยันตัวตน SSO เข้าใช้งานแอปพลิเคชันที่เชื่อมต่อ
        </div>
      )}

      <div className="mt-6 flex justify-center gap-2 border-t border-slate-100 pt-4">
        <button
          onClick={onSignOut}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 px-3.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
        >
          <LogOut className="h-3.5 w-3.5" /> ออกจากระบบ
        </button>
        <button
          onClick={() => {
            if (confirm('ลบบัญชีและข้อมูลทั้งหมดถาวร ยืนยันหรือไม่?')) onDelete()
          }}
          className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3.5 py-1.5 text-xs font-medium text-red-600 hover:bg-red-100"
        >
          <Trash2 className="h-3.5 w-3.5" /> ลบบัญชีผู้ใช้
        </button>
      </div>
    </div>
  )
}
