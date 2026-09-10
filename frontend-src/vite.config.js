import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const backendUrl = () => process.env.VITE_BACKEND_URL || 'http://localhost:8000'

/**
 * Silent API proxy — forwards /api/* to the FastAPI backend on port 8000.
 * Handles CORS by proxying requests through the Vite dev server.
 * If the backend is unreachable, returns a clean JSON 503 for mock mode fallback.
 */
function silentApiProxy() {
  return {
    name: 'silent-api-proxy',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        // Proxy both /api/* and /health to backend
        if (!req.url || (!req.url.startsWith('/api') && req.url !== '/health')) return next()

        const chunks = []
        req.on('data', (chunk) => chunks.push(chunk))
        req.on('end', async () => {
          const headers = { ...req.headers }
          delete headers.host
          delete headers.origin
          delete headers.referer

          // Map frontend /api/health -> backend /health
          let targetPath = req.url
          if (targetPath === '/api/health') targetPath = '/health'
          
          const targetUrl = `${backendUrl()}${targetPath}`

          try {
            const upstream = await fetch(targetUrl, {
              method: req.method,
              headers,
              body: ['GET', 'HEAD'].includes(req.method ?? 'GET')
                ? undefined
                : Buffer.concat(chunks),
              redirect: 'manual',
            })

            res.statusCode = upstream.status
            upstream.headers.forEach((value, key) => {
              if (!['content-encoding', 'transfer-encoding', 'connection'].includes(key)) {
                res.setHeader(key, value)
              }
            })
            // Add CORS headers to allow frontend access
            res.setHeader('Access-Control-Allow-Origin', '*')
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS')
            res.setHeader('Access-Control-Allow-Headers', '*')
            res.end(Buffer.from(await upstream.arrayBuffer()))
          } catch (err) {
            console.warn('[proxy] Backend unreachable:', err.message)
            res.statusCode = 503
            res.setHeader('Content-Type', 'application/json')
            res.setHeader('Access-Control-Allow-Origin', '*')
            res.end(JSON.stringify({ detail: 'FastAPI backend offline — running in mock mode' }))
          }
        })
        req.on('error', () => {
          if (!res.headersSent) {
            res.statusCode = 503
            res.setHeader('Content-Type', 'application/json')
            res.setHeader('Access-Control-Allow-Origin', '*')
          }
          res.end()
        })
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), silentApiProxy()],
  server: {
    port: 5173,
    open: false,
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        main: 'index.html',
      },
      output: {
        entryFileNames: 'script.js',
        chunkFileNames: 'script.js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name?.endsWith('.css')) return 'style.css'
          return assetInfo.name || '[name].[ext]'
        },
      },
    },
  },
})
