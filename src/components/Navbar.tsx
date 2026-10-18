import { LogOut, ShieldCheck } from 'lucide-react'
import type { UserProfile } from '../types/auth'

export type Page = 'home' | 'admin'

interface Props {
  page: Page
  setPage: (p: Page) => void
  profile: UserProfile | null
  loading?: boolean
  onSignOut: () => void
}

export default function Navbar({ page, setPage, profile, loading, onSignOut }: Props) {
  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-600 text-white shadow-sm">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <h1 className="font-bold text-slate-900 text-base leading-tight">WhyYouKnow Auth</h1>
            <p className="text-xs text-slate-500">Identity & OAuth 2.0 Provider</p>
          </div>
        </div>

        <nav className="flex items-center gap-4">
          <button
            onClick={() => setPage('home')}
            className={`text-sm font-medium transition ${
              page === 'home' ? 'text-blue-600' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            หน้าหลัก
          </button>

          {loading ? (
            <div className="h-8 w-24 animate-pulse rounded-lg bg-slate-100" />
          ) : (
            <>
              {profile?.is_admin && (
                <button
                  onClick={() => setPage('admin')}
                  className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                    page === 'admin'
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-600 hover:bg-slate-100'
                  }`}
                >
                  แผงควบคุม Admin
                </button>
              )}

              {profile && (
                <div className="ml-2 flex items-center gap-3 border-l border-slate-200 pl-4">
                  {profile.picture ? (
                    <img
                      src={profile.picture}
                      alt={profile.name}
                      referrerPolicy="no-referrer"
                      className="h-8 w-8 rounded-full ring-1 ring-slate-200"
                    />
                  ) : (
                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200 text-xs font-semibold">
                      {profile.name.charAt(0)}
                    </div>
                  )}
                  <span className="hidden sm:inline text-xs font-medium text-slate-700 truncate max-w-[120px]">
                    {profile.name}
                  </span>
                  <button
                    onClick={onSignOut}
                    title="ออกจากระบบ"
                    className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
                  >
                    <LogOut className="h-4 w-4" />
                  </button>
                </div>
              )}
            </>
          )}
        </nav>
      </div>
    </header>
  )
}
