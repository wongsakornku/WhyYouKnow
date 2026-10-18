import http from 'http'
import https from 'https'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const PORT = parseInt(process.env.PORT || '80', 10)
const HOST = '0.0.0.0'
const DIST_DIR = path.join(__dirname, 'dist')
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8000'

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
}

let parsedBackend
try {
  parsedBackend = new URL(BACKEND_URL)
} catch {
  parsedBackend = new URL('http://localhost:8000')
}
const backendTransport = parsedBackend.protocol === 'https:' ? https : http

const server = http.createServer((req, res) => {
  const urlPath = req.url ? req.url.split('?')[0] : '/'

  // 1. Reverse Proxy for /api requests to Backend
  if (urlPath.startsWith('/api')) {
    const proxyHeaders = { ...req.headers, host: parsedBackend.host }
    const clientIp = req.socket.remoteAddress
    if (clientIp) {
      proxyHeaders['x-forwarded-for'] = req.headers['x-forwarded-for']
        ? `${req.headers['x-forwarded-for']}, ${clientIp}`
        : clientIp
    }

    const proxyReq = backendTransport.request(
      {
        protocol: parsedBackend.protocol,
        hostname: parsedBackend.hostname,
        port: parsedBackend.port || (parsedBackend.protocol === 'https:' ? 443 : 80),
        method: req.method,
        path: req.url,
        headers: proxyHeaders,
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode || 500, proxyRes.headers)
        proxyRes.pipe(res, { end: true })
      }
    )

    proxyReq.on('error', (err) => {
      console.error('[Proxy Error]:', err.message)
      if (!res.headersSent) {
        res.statusCode = 502
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ detail: 'Bad Gateway: Backend unreachable' }))
      }
    })

    req.pipe(proxyReq, { end: true })
    return
  }

  // 2. Serve static SPA assets
  const safePath = path.normalize(urlPath).replace(/^(\.\.[/\\])+/, '')
  let filePath = path.join(DIST_DIR, safePath === '/' ? 'index.html' : safePath)

  if (!filePath.startsWith(DIST_DIR)) {
    res.statusCode = 403
    res.end('Forbidden')
    return
  }

  fs.stat(filePath, (err, stats) => {
    // SPA Fallback: if file doesn't exist or is a directory, serve index.html
    if (err || !stats.isFile()) {
      filePath = path.join(DIST_DIR, 'index.html')
    }

    const ext = path.extname(filePath).toLowerCase()
    const contentType = MIME_TYPES[ext] || 'application/octet-stream'

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        res.statusCode = 500
        res.end('Server Error: Failed to read file')
        return
      }
      res.setHeader('Content-Type', contentType)
      res.setHeader('Cache-Control', ext === '.html' ? 'no-cache' : 'public, max-age=31536000, immutable')
      res.statusCode = 200
      res.end(content)
    })
  })
})

server.listen(PORT, HOST, () => {
  console.log(`[Frontend] Server listening on http://${HOST}:${PORT}`)
  console.log(`[Frontend] Reverse proxying /api to ${BACKEND_URL}`)
})
