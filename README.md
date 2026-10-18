# WhyYouKnow — Google Sign-In & OAuth 2.0 SSO Provider

ระบบศูนย์กลางยืนยันตัวตน (**Identity Provider / SSO Provider**) ที่รองรับการเข้าสู่ระบบด้วย **Google Sign-In (Google Identity Services)** และเปิดให้เว็บภายนอก (เช่น `app1`, `app2`) มาเชื่อมต่อขอใช้สิทธิ์ยืนยันตัวตนผ่านโปรโตคอลมาตรฐาน **OAuth 2.0 (Authorization Code Flow + PKCE)** พร้อมระบบจัดการผู้ใช้รายแอปพลิเคชัน (**User Management by App**), การควบคุมคำเชิญ (**Per-App Invites**), วงจรชีวิตของโทเค็น (**Refresh Tokens & Revocation**), และระบบบันทึกตรวจสอบกิจกรรม (**Audit Trail & Export Logs**)

---

## 🌟 จุดเด่นและฟีเจอร์หลัก (Features)

### 1. Google Identity Services (GIS)
- เข้าสู่ระบบด้วยบัญชี Google อย่างปลอดภัย
- ตรวจสอบความถูกต้องและความสมบูรณ์ (Signature, Audience, Expiry) ฝั่ง Server ผ่าน `google-auth`
- รองรับการสร้างบัญชีอัตโนมัติเมื่อเข้าสู่ระบบครั้งแรก

### 2. OAuth 2.0 & Token Lifecycle (RFC 6749, RFC 7009, RFC 7636)
- **Confidential Client:** สำหรับเว็บที่มี Backend Server (ใช้ `client_id` + `client_secret`)
- **Public Client:** สำหรับ Single Page Application (SPA) หรือ Mobile (บังคับใช้ **PKCE S256**)
- **Short-lived Access Tokens:** กำหนดอายุ Access Token ได้ผ่าน `OAUTH_ACCESS_TOKEN_MINUTES` (ค่าเริ่มต้น 60 นาที)
- **Refresh Token Rotation:** ออก Refresh Token พร้อม Access Token เมื่อแลกเปลี่ยน Authorization Code โดยทุกครั้งที่มีการใช้ Refresh Token จะได้ Token ชุดใหม่เสมอ และ Token เก่าจะถูกเพิกถอน
- **Refresh Token Reuse Detection:** หากมีผู้นำ Refresh Token ที่ถูกเพิกถอนไปแล้วมาขอใช้ซ้ำ ระบบจะตรวจจับการโจรกรรมและเพิกถอน Token ทั้งหมดของ User ในแอปนั้นทันที
- **RFC 7009 Token Revocation (`POST /api/oauth/revoke`):** รองรับการเพิกถอนทั้ง Access Token และ Refresh Token เมื่อผู้ใช้ออกจากระบบในแอปปลายทาง

### 3. การจัดการแอปพลิเคชัน OAuth (Client Management)
- **เปิด/ปิดการใช้งาน (Enable / Disable):** สั่งระงับแอปพลิเคชันชั่วคราวได้ทันที เมื่อปิดการใช้งานจะไม่สามารถขอสิทธิ์หรือแลกเปลี่ยน Token ได้
- **โหมดการเข้าถึง (Access Mode):**
  - **Open Mode:** ผู้ใช้ทุกคนในระบบสามารถล็อกอินเข้าใช้งานแอปนี้ได้
  - **Invite Only Mode:** จำกัดให้เฉพาะผู้ใช้ที่อยู่ในรายชื่อคำเชิญ (`app_invites`) เท่านั้นที่สามารถเข้าถึงแอปได้
- **ระบบคำเชิญล่วงหน้า (Per-App Invites):** แอดมินสามารถระบุอีเมลและตำแหน่งเริ่มต้น (`admin`, `member`, `viewer`) ล่วงหน้าได้ เมื่อผู้ใช้คนนั้นล็อกอินครั้งแรก ระบบจะกำหนด Role และให้สิทธิ์เข้าถึงทันที
- **สลับ Client Secret (Rotate Secret):** สร้าง Client Secret ใหม่ได้ทันทีเมื่อมีความเสี่ยง Secret รั่วไหล โดย Secret เดิมจะถูกยกเลิกทันที
- **แก้ไขชื่อแอปและ Redirect URIs:** ปรับแต่งข้อมูลแอปได้ตลอดเวลา

### 4. ระบบจัดการผู้ใช้รายแอป (Users by App)
- **บันทึกความเชื่อมโยงอัตโนมัติ:** เมื่อผู้ใช้ยินยอมล็อกอินเข้าแอป ระบบจะลงทะเบียนผู้ใช้เข้ากับแอปนั้นทันที
- **กำหนด Role แยกรายแอป:** ผู้ดูแลระบบสามารถกำหนดตำแหน่งของผู้ใช้ในแต่ละแอปได้อิสระ (`member`, `admin`, `viewer`)
- **ส่ง Role ไปกับ Userinfo:** ที่ `/api/oauth/userinfo` จะแนบฟิลด์ `"role"` ของแอปนั้นกลับไป เพื่อให้เว็บปลายทางนำไปคุมสิทธิ์ในระบบตัวเองได้ทันที
- **การตัดสิทธิ์ทันที (Revoke Access):** แอดมินสามารถกด "ตัดสิทธิ์" ผู้ใช้เฉพาะแอปได้ โดย Token ทั้งหมดของแอปนั้นจะถูกเพิกถอนทันที

### 5. ระบบจัดการผู้ใช้ส่วนกลาง (Global User Management)
- **ตรวจสอบข้อมูลเชิงลึก (Inspect User):** ดูรายการแอปพลิเคชันทั้งหมดที่ผู้ใช้เชื่อมต่อ, จำนวน Web Sessions และ OAuth Tokens ที่กำลังใช้งาน
- **เตะออกจากระบบทุกอุปกรณ์ (Force Logout Everywhere):** เพิกถอน Session และ OAuth Token ทั้งหมดของผู้ใช้ในคลิกเดียว
- **ระงับบัญชีผู้ใช้ (Suspend / Unsuspend):** ระงับบัญชีผู้ใช้ชั่วคราว บัญชีที่ถูกระงับจะไม่สามารถเข้าสู่ระบบหรือใช้ Token ใดๆ ได้
- **จัดการสิทธิ์ Admin ในฐานข้อมูล:** แต่งตั้งหรือถอดสิทธิ์ Admin ได้ผ่านหน้า UI โดยมีระบบป้องกัน **Super Admin** (ผู้ที่มีอีเมลตรงกับ `ADMIN_EMAILS` ใน `.env` จะไม่สามารถถูกปลดหรือระงับได้)

### 6. ระบบบันทึกและตรวจสอบกิจกรรม (Audit Trail & Log Export)
- **บันทึกทุกกิจกรรมด้านความปลอดภัย:** การล็อกอิน, การออกจากระบบ, การให้สิทธิ์แอป, การออก Token, การหมุนเวียน Refresh Token, การตรวจพบ Reuse, การเปลี่ยน Role, การตัดสิทธิ์, การระงับบัญชี, และการตั้ง Admin
- **ค้นหาและกรองละเอียด:** ค้นหา Real-time ตามอีเมล, ชื่อแอป หรือรายละเอียด พร้อมตัวกรองแยกตามประเภทกิจกรรม และแยกตามแอปพลิเคชัน
- **ส่งออกข้อมูล (Export Logs):**
  - **CSV:** รองรับภาษาไทยสมบูรณ์ด้วย UTF-8 BOM และป้องกัน Formula Injection
  - **JSON:** โครงสร้างข้อมูลดิบสำหรับส่งต่อให้ระบบ Security หรือ SIEM
- **การเก็บรักษา (Retention):** ลบข้อมูลเก่าอัตโนมัติเกินกำหนด (ค่าเริ่มต้น 90 วัน)

### 7. หน้าหลักแดชบอร์ดอัจฉริยะ (Dynamic Home Dashboard)
- **ปรับเปลี่ยนมุมมองอัตโนมัติตามสิทธิ์ (Role-Adaptive UI):**
  - **Admin View:** แสดง 4 การ์ดสถิติระบบแบบเรียลไทม์ (แอปทั้งหมด, ผู้ใช้ในระบบ, Active Web Sessions, Active OAuth Tokens), ทางลัด Quick Actions ไปยังหน้าจัดการต่างๆ, และตารางกิจกรรมความปลอดภัยล่าสุด (Recent Security Activity)
  - **User Portal View:** พอร์ทัลข้อมูลส่วนบุคคล แสดงโปรไฟล์, รายการแอปภายนอกที่เคยให้สิทธิ์เชื่อมต่อ (Connected Apps) พร้อมบทบาท (Role) และ**ปุ่มตัดการเชื่อมต่อแอปได้ด้วยตนเอง (Self-Service App Disconnect)**, รวมถึงประวัติกิจกรรมล่าสุดของตนเอง
- **API Endpoints:**
  - `GET /api/admin/dashboard-stats` (เฉพาะ Admin)
  - `GET /api/me/dashboard` (ดึงข้อมูลพอร์ทัลและแอปของผู้ใช้)
  - `DELETE /api/me/apps/{client_id}` (ผู้ใช้เพิกถอนสิทธิ์แอปของตนเอง)

---

## 🛠️ เทคโนโลยีที่ใช้ (Tech Stack)

- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Lucide Icons, `@react-oauth/google`
- **Backend:** Python 3, FastAPI, Uvicorn, PyMySQL, Cryptography, `google-auth-library`
- **Database:** MySQL / MariaDB 12 (InnoDB, Foreign Key CASCADE, Charset `utf8mb4`)
- **Testing:** Pytest, HTTPX

---

## 📂 โครงสร้างฐานข้อมูล (Database Schema)

* **`users`**: ข้อมูลบัญชีผู้ใช้หลัก (`id`, `google_sub`, `email`, `name`, `picture`, `status`, `is_admin`, `created_at`, `last_login_at`)
* **`oauth_clients`**: รายชื่อแอปภายนอก (`client_id`, `client_secret_hash`, `client_name`, `redirect_uris`, `is_confidential`, `is_active`, `access_mode`)
* **`app_invites`**: คำเชิญเข้าแอปในโหมด Invite-Only (`id`, `client_id`, `email`, `initial_role`, `created_at`)
* **`app_users`**: ตารางเชื่อมโยงสิทธิ์ผู้ใช้รายแอป (`client_id`, `user_id`, `role`, `status`, `last_accessed_at`)
* **`oauth_codes`**: Authorization Code ชั่วคราว (Single-use, 5 นาที, รองรับ `code_challenge` สำหรับ PKCE)
* **`oauth_tokens`**: Access Token ที่ออกให้แอปภายนอก (มีอายุใช้งาน)
* **`oauth_refresh_tokens`**: Refresh Token พร้อมระบบหมุนเวียนและการตรวจจับการใช้ซ้ำ (`is_revoked`)
* **`sessions`**: เซสชันการล็อกอินในระบบหลัก (SHA-256 Hash)
* **`audit_logs`**: บันทึกกิจกรรมด้านความปลอดภัยและระบบ Audit Trail พร้อม Index
* **`login_logs`**: บันทึกประวัติการล็อกอิน (IP ถูกเข้ารหัสเป็น HMAC-SHA256)

---

## ⚙️ การเริ่มใช้งาน (Getting Started)

### 1. ตั้งค่า `.env`
```env
GOOGLE_CLIENT_ID=391951300708-4vudpihrt1m3334i3rs4ml525kas0etp.apps.googleusercontent.com
VITE_GOOGLE_CLIENT_ID=391951300708-4vudpihrt1m3334i3rs4ml525kas0etp.apps.googleusercontent.com
IP_HMAC_SECRET=your-random-secret
ADMIN_EMAILS=your.email@gmail.com
ALLOWED_ORIGINS=http://localhost:5173

DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASS=Welcome1
DB_NAME=kno

# วงจรชีวิตของโทเค็น
OAUTH_ACCESS_TOKEN_MINUTES=60
OAUTH_REFRESH_TOKEN_DAYS=30

# พร็อกซีที่เชื่อถือได้สำหรับ X-Forwarded-For (เช่น 127.0.0.1, 10.0.0.0/8 หรือ *)
TRUSTED_PROXIES=127.0.0.1

# กำหนดระยะเวลาเก็บ Audit Logs (วัน)
AUDIT_LOG_RETENTION_DAYS=90
```

### 2. รันเซิร์ฟเวอร์ (Service Manager)

สามารถใช้สคริปต์ `service.sh` เพื่อจัดการทั้ง Backend และ Frontend ได้อย่างง่ายดาย:

```bash
# เริ่มต้นทั้งระบบ (Backend :8000 + Frontend :5173)
./service.sh start

# ตรวจสอบสถานะการทำงานและ Health Check
./service.sh status

# หยุดการทำงานทั้งหมด
./service.sh stop

# รีสตาร์ทระบบ
./service.sh restart

# ดู Log ล่าสุด (หรือระบุ backend / frontend)
./service.sh logs
```

*(หรือหากต้องการรันแยก Terminal แบบเดิม: Backend รัน `server/.venv/bin/uvicorn main:app --app-dir server --port 8000 --reload` และ Frontend รัน `npm run dev`)*

เปิดเบราว์เซอร์ไปที่: **http://localhost:5173**

---

## 🔌 ตัวอย่างการเชื่อมต่อ OAuth 2.0 (Client Integration)

### 1. ขอสิทธิ์เข้าใช้งาน (Authorization Request)
ส่งผู้ใช้ไปยังหน้า Authorize:
```text
GET /api/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```

### 2. แลกเปลี่ยน Authorization Code เป็น Token
```bash
POST /api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
&code=AUTHORIZATION_CODE
&redirect_uri=YOUR_REDIRECT_URI
&code_verifier=CODE_VERIFIER
```
**Response:**
```json
{
  "access_token": "wyk_at_...",
  "refresh_token": "wyk_rt_...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 3. ขอ Access Token ใหม่ด้วย Refresh Token (Rotation)
```bash
POST /api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
&refresh_token=wyk_rt_...
```
**Response:**
```json
{
  "access_token": "wyk_at_NEW...",
  "refresh_token": "wyk_rt_NEW...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 4. เพิกถอน Token เมื่อออกจากระบบ (RFC 7009 Revoke)
```bash
POST /api/oauth/revoke
Content-Type: application/x-www-form-urlencoded

client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
&token=wyk_rt_...
&token_type_hint=refresh_token
```

### 5. ดึงข้อมูลผู้ใช้และ Role
```bash
GET /api/oauth/userinfo
Authorization: Bearer wyk_at_...
```
**Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "name": "User Name",
  "picture": "https://...",
  "role": "member"
}
```

---

## 🧪 การรันชุดทดสอบ (Automated Tests)

```bash
server/.venv/bin/pytest server/tests/test_api.py -v
```
*(ครอบคลุมการทดสอบทั้งหมด 27 รายการ: Google Auth, CSRF, Secure Headers, Token Verification, Cascade Delete, Confidential/Public PKCE Flow, Rate Limiting, CSV Injection Defense, Trusted Proxies IP, Client Management, Refresh Token Lifecycle & Reuse Detection, Invite-Only Access, Force Logout, Account Suspension, Admin Management in DB, และ Dashboard Stats & User App Disconnect)*
