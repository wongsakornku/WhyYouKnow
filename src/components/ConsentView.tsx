import { useEffect, useState } from 'react'
import { CheckCircle2, ShieldAlert, ShieldCheck } from 'lucide-react'
import { GoogleLogin, type CredentialResponse } from '@react-oauth/google'
import { api } from '../api'
import type { ClientInfo, UserProfile } from '../types/auth'

interface Props {
  profile: UserProfile | null
  onLoginSuccess: (res: CredentialResponse) => void
  clientId: string
  redirectUri: string
  state?: string | null
  codeChallenge?: string | null
  codeChallengeMethod?: string | null
}

export default function ConsentView({
  profile,
  onLoginSuccess,
  clientId,
  redirectUri,
  state,
  codeChallenge,
  codeChallengeMethod,
}: Props) {
  const [clientInfo, setClientInfo] = useState<ClientInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [authError, setAuthError] = useState<string | null>(null)
  const [isHumanVerified, setIsHumanVerified] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const botDetectionEnabled = Boolean(clientInfo?.attack_protection?.bot_detection)

  useEffect(() => {
    api
      .getClientInfo(clientId)
      .then((info) => {
        if (!info.redirect_uris.includes(redirectUri)) {
          setLoadError(`Redirect URI "${redirectUri}" ไม่ได้รับอนุญาตสำหรับแอปนี้`)
        } else {
          setClientInfo(info)
        }
      })
      .catch((err) => {
        setLoadError(err.message || 'ไม่พบแอปพลิเคชันที่ระบุ')
      })
      .finally(() => setLoading(false))
  }, [clientId, redirectUri])

  const handleAuthorize = async () => {
    if (botDetectionEnabled && !isHumanVerified) {
      setAuthError('กรุณายืนยันว่าคุณไม่ใช่โปรแกรมอัตโนมัติก่อนดำเนินการต่อ (Bot Verification Required)')
      return
    }
    setSubmitting(true)
    setAuthError(null)
    try {
      const res = await api.authorizeOAuth({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: codeChallenge || undefined,
        code_challenge_method: codeChallengeMethod || 'S256',
        bot_token: isHumanVerified || !botDetectionEnabled ? 'human-verified' : undefined,
      })
      const sep = res.redirect_uri.includes('?') ? '&' : '?'
      const stateParam = state ? `&state=${encodeURIComponent(state)}` : ''
      window.location.href = `${res.redirect_uri}${sep}code=${encodeURIComponent(res.code)}${stateParam}`
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'เกิดข้อผิดพลาดในการอนุญาต'
      setAuthError(msg)
      setSubmitting(false)
    }
  }

  const handleDeny = () => {
    const sep = redirectUri.includes('?') ? '&' : '?'
    const stateParam = state ? `&state=${encodeURIComponent(state)}` : ''
    window.location.href = `${redirectUri}${sep}error=access_denied${stateParam}`
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-md rounded-2xl bg-white p-8 text-center shadow">
        <p className="text-slate-500">กำลังตรวจสอบข้อมูลแอปพลิเคชัน...</p>
      </div>
    )
  }

  if (loadError || !clientInfo) {
    return (
      <div className="mx-auto max-w-md rounded-2xl bg-white p-8 text-center shadow">
        <ShieldAlert className="mx-auto h-12 w-12 text-red-500" />
        <h2 className="mt-3 text-lg font-semibold text-slate-800">คำขอเชื่อมต่อไม่ถูกต้อง</h2>
        <p className="mt-2 text-sm text-red-600">{loadError || 'ไม่พบข้อมูลแอป'}</p>
        <button
          onClick={() => (window.location.href = '/')}
          className="mt-6 rounded-lg bg-slate-800 px-4 py-2 text-sm text-white hover:bg-slate-700"
        >
          กลับหน้าหลัก
        </button>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-md rounded-2xl bg-white p-8 shadow">
      <div className="text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-50 text-blue-600">
          <ShieldCheck className="h-8 w-8" />
        </div>
        <h2 className="mt-4 text-xl font-bold text-slate-800">เข้าสู่ระบบด้วย Google</h2>
        <p className="mt-1 text-sm text-slate-600">
          <span className="font-semibold text-slate-900">{clientInfo.client_name}</span>{' '}
          ต้องการขอสิทธิ์เข้าถึงบัญชีของคุณ
        </p>
      </div>

      <div className="mt-6 rounded-xl border border-slate-100 bg-slate-50 p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
          ข้อมูลที่แอปจะได้รับ:
        </h3>
        <ul className="mt-3 space-y-2 text-sm text-slate-700">
          <li className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-600" />
            <span>ชื่อ-นามสกุลของคุณ</span>
          </li>
          <li className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-600" />
            <span>ที่อยู่อีเมลของคุณ</span>
          </li>
          <li className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-600" />
            <span>รูปภาพโปรไฟล์ของคุณ</span>
          </li>
        </ul>
      </div>

      {!profile ? (
        <div className="mt-6 text-center">
          <p className="mb-4 text-sm text-slate-500">
            กรุณาเข้าสู่ระบบด้วย Google ก่อนเพื่อดำเนินการต่อ
          </p>
          <div className="flex justify-center">
            <GoogleLogin
              onSuccess={onLoginSuccess}
              onError={() => setAuthError('เข้าสู่ระบบด้วย Google ไม่สำเร็จ')}
            />
          </div>
        </div>
      ) : (
        <>
          <div className="mt-6 flex items-center gap-3 rounded-xl border border-slate-200 bg-white p-3">
            {profile.picture ? (
              <img
                src={profile.picture}
                alt={profile.name}
                referrerPolicy="no-referrer"
                className="h-10 w-10 rounded-full"
              />
            ) : (
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-200 font-semibold text-slate-700">
                {profile.name.charAt(0)}
              </div>
            )}
            <div className="min-w-0 flex-1 text-left">
              <p className="truncate text-sm font-medium text-slate-900">{profile.name}</p>
              <p className="truncate text-xs text-slate-500">{profile.email}</p>
            </div>
          </div>

          {botDetectionEnabled && (
            <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3.5 text-left transition-colors">
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2.5 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={isHumanVerified}
                    onChange={(e) => {
                      setIsHumanVerified(e.target.checked)
                      if (e.target.checked && authError) {
                        setAuthError(null)
                      }
                    }}
                    className="h-5 w-5 rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                  />
                  <span className="text-sm font-medium text-slate-700">
                    ฉันไม่ใช่โปรแกรมอัตโนมัติ (I am not a robot)
                  </span>
                </label>
                <div className="flex flex-col items-end pl-2">
                  <ShieldCheck className={`h-5 w-5 ${isHumanVerified ? 'text-emerald-600' : 'text-slate-400'}`} />
                  <span className="text-[10px] text-slate-400">Bot Shield</span>
                </div>
              </div>
            </div>
          )}

          {authError && (
            <div className="mt-4 flex items-start gap-2 rounded-xl bg-red-50 p-3 text-left border border-red-100">
              <ShieldAlert className="h-5 w-5 flex-shrink-0 text-red-500 mt-0.5" />
              <p className="text-xs text-red-600 leading-relaxed">{authError}</p>
            </div>
          )}

          <div className="mt-6 flex gap-3">
            <button
              onClick={handleDeny}
              disabled={submitting}
              className="flex-1 rounded-xl border border-slate-300 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
            >
              ปฏิเสธ
            </button>
            <button
              onClick={handleAuthorize}
              disabled={submitting || (botDetectionEnabled && !isHumanVerified)}
              className="flex-1 rounded-xl bg-blue-600 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {submitting ? 'กำลังอนุญาต...' : 'ยินยอม'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

