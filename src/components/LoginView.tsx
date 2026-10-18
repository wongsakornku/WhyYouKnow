import { GoogleLogin, type CredentialResponse } from '@react-oauth/google'

interface Props {
  onSuccess: (res: CredentialResponse) => void
  error: string | null
  onError: () => void
}

export default function LoginView({ onSuccess, onError, error }: Props) {
  return (
    <div className="rounded-2xl bg-white p-8 text-center shadow">
      <h2 className="text-xl font-semibold text-slate-800">เข้าสู่ระบบด้วย Google</h2>
      <p className="mt-1 mb-6 text-sm text-slate-500">กดปุ่มด้านล่างเพื่อทดสอบ Google Sign-In</p>
      <div className="flex justify-center">
        <GoogleLogin onSuccess={onSuccess} onError={onError} />
      </div>
      {error && (
        <p className="mt-4 rounded-lg bg-red-50 p-3 text-sm text-red-600">{error}</p>
      )}
    </div>
  )
}
