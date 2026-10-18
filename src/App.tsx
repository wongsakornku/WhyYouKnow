import { useEffect, useState } from 'react'
import { GoogleOAuthProvider, googleLogout, type CredentialResponse } from '@react-oauth/google'
import { api } from './api'
import Navbar, { type Page } from './components/Navbar'
import LoginView from './components/LoginView'
import DashboardView from './components/DashboardView'
import AdminPage from './components/AdminPage'
import ConsentView from './components/ConsentView'
import type { UserProfile } from './types/auth'

const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID as string

export default function App() {
  const [profile, setProfile] = useState<UserProfile | null>(null)
  const [loadingAuth, setLoadingAuth] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState<Page>('home')
  const [adminTab, setAdminTab] = useState<'apps' | 'app_users' | 'all_users' | 'audit_logs'>('apps')

  // Parse OAuth authorize query parameters
  const params = new URLSearchParams(window.location.search)
  const oauthClientId = params.get('client_id')
  const oauthRedirectUri = params.get('redirect_uri')
  const oauthState = params.get('state')
  const oauthCodeChallenge = params.get('code_challenge')
  const oauthCodeChallengeMethod = params.get('code_challenge_method')
  const isOauthAuthorizeFlow = Boolean(oauthClientId && oauthRedirectUri)

  useEffect(() => {
    api
      .me()
      .then(setProfile)
      .catch(() => setProfile(null))
      .finally(() => setLoadingAuth(false))
  }, [])

  const handleSuccess = async (res: CredentialResponse) => {
    if (!res.credential) {
      setError('ไม่ได้รับ credential จาก Google')
      return
    }
    try {
      const loggedIn = await api.login(res.credential)
      const user = loggedIn.is_admin !== undefined ? loggedIn : await api.me()
      setProfile(user)
      setError(null)
    } catch {
      setError('เซิร์ฟเวอร์ปฏิเสธการเข้าสู่ระบบ')
    }
  }

  const handleSignOut = async () => {
    googleLogout()
    await api.logout().catch(() => undefined)
    setProfile(null)
    setPage('home')
  }

  const handleNavigateAdminTab = (tab: 'apps' | 'app_users' | 'all_users' | 'audit_logs') => {
    setAdminTab(tab)
    setPage('admin')
  }

  return (
    <GoogleOAuthProvider clientId={clientId}>
      <div className="min-h-screen bg-slate-100">
        {!isOauthAuthorizeFlow && (
          <Navbar
            page={page}
            setPage={(p) => {
              if (p === 'admin') setAdminTab('apps')
              setPage(p)
            }}
            profile={profile}
            loading={loadingAuth}
            onSignOut={handleSignOut}
          />
        )}

        <main className="mx-auto max-w-5xl space-y-4 p-4">
          {loadingAuth ? (
            <div className="mx-auto max-w-md rounded-2xl bg-white p-12 text-center shadow-sm">
              <div className="mx-auto h-9 w-9 animate-spin rounded-full border-3 border-blue-200 border-t-blue-600" />
              <p className="mt-4 text-sm font-medium text-slate-500">กำลังตรวจสอบข้อมูลการเข้าสู่ระบบ...</p>
            </div>
          ) : isOauthAuthorizeFlow ? (
            <ConsentView
              profile={profile}
              onLoginSuccess={handleSuccess}
              clientId={oauthClientId!}
              redirectUri={oauthRedirectUri!}
              state={oauthState}
              codeChallenge={oauthCodeChallenge}
              codeChallengeMethod={oauthCodeChallengeMethod}
            />
          ) : (
            <>
              {/* 2. Admin Dashboard */}
              {page === 'admin' &&
                (profile?.is_admin ? (
                  <AdminPage key={adminTab} initialTab={adminTab} />
                ) : (
                  <div className="rounded-2xl bg-white p-8 text-center shadow">
                    <p className="text-sm text-slate-500">
                      กรุณาเข้าสู่ระบบด้วยบัญชีแอดมินก่อนเข้าใช้งาน
                    </p>
                  </div>
                ))}

              {/* 3. Home / Dashboard / Login */}
              {page === 'home' &&
                (profile ? (
                  <DashboardView
                    profile={profile}
                    onSignOut={handleSignOut}
                    onNavigateAdminTab={handleNavigateAdminTab}
                  />
                ) : (
                  <LoginView
                    onSuccess={handleSuccess}
                    onError={() => setError('เข้าสู่ระบบด้วย Google ไม่สำเร็จ')}
                    error={error}
                  />
                ))}
            </>
          )}
        </main>
      </div>
    </GoogleOAuthProvider>
  )
}
