import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import type { TokenResponse } from '../types'

const CLIENT_ID = import.meta.env.VITE_ADMIN_CLIENT_ID || 'internal_admin_console'
const CLIENT_SECRET = import.meta.env.VITE_ADMIN_CLIENT_SECRET || ''
const SCOPE = 'manage:system manage:clients'
const REDIRECT_URI = window.location.origin + '/callback'

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
}

interface AuthContextType extends AuthState {
  login: () => void
  logout: () => void
  handleCallback: (code: string, state: string) => Promise<boolean>
}

const AuthContext = createContext<AuthContextType | null>(null)

function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return base64URLEncode(array)
}

function sha256(message: Uint8Array): Uint8Array {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]
  const msg = new Uint8Array(message.length + 9 + 64 - ((message.length + 9) % 64))
  msg.set(message)
  msg[message.length] = 0x80
  const bits = message.length * 8
  const view = new DataView(msg.buffer)
  view.setUint32(msg.length - 8 + 4, bits >>> 0, false)
  view.setUint32(msg.length - 8, (bits / 0x100000000) >>> 0, false)

  let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
  for (let i = 0; i < msg.length; i += 64) {
    const W = new Uint32Array(64)
    for (let t = 0; t < 16; t++) W[t] = view.getUint32(i + t * 4, false)
    for (let t = 16; t < 64; t++) {
      const s0 = ((W[t - 15] >>> 7) | (W[t - 15] << 25)) ^ ((W[t - 15] >>> 18) | (W[t - 15] << 14)) ^ (W[t - 15] >>> 3)
      const s1 = ((W[t - 2] >>> 17) | (W[t - 2] << 15)) ^ ((W[t - 2] >>> 19) | (W[t - 2] << 13)) ^ (W[t - 2] >>> 10)
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0
    }
    let [a, b, c, d, e, f, g, h] = H
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))
      const ch = (e & f) ^ (~e & g)
      const T1 = (h + S1 + ch + K[t] + W[t]) >>> 0
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const T2 = (S0 + maj) >>> 0
      h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0
    }
    H = [H[0] + a, H[1] + b, H[2] + c, H[3] + d, H[4] + e, H[5] + f, H[6] + g, H[7] + h].map(x => x >>> 0)
  }
  const out = new Uint8Array(32)
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (H[i] >>> 24) & 0xff; out[i * 4 + 1] = (H[i] >>> 16) & 0xff
    out[i * 4 + 2] = (H[i] >>> 8) & 0xff; out[i * 4 + 3] = H[i] & 0xff
  }
  return out
}

function generateCodeChallenge(verifier: string): string {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  return base64URLEncode(sha256(data))
}

function base64URLEncode(buffer: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function generateState(): string {
  const array = new Uint8Array(16)
  crypto.getRandomValues(array)
  return base64URLEncode(array)
}

const TOKEN_KEY = 'admin_tokens'

function loadTokens(): AuthState {
  try {
    const raw = localStorage.getItem(TOKEN_KEY)
    if (!raw) return { accessToken: null, refreshToken: null, isAuthenticated: false }
    const data = JSON.parse(raw) as AuthState
    if (data.accessToken) {
      return { ...data, isAuthenticated: true }
    }
  } catch { /* ignore */ }
  return { accessToken: null, refreshToken: null, isAuthenticated: false }
}

function saveTokens(accessToken: string, refreshToken?: string) {
  localStorage.setItem(TOKEN_KEY, JSON.stringify({ accessToken, refreshToken }))
}

function clearTokens() {
  localStorage.removeItem(TOKEN_KEY)
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState>(loadTokens)

  const login = useCallback(() => {
    const verifier = generateCodeVerifier()
    const state = generateState()
    sessionStorage.setItem('pkce_verifier', verifier)
    sessionStorage.setItem('pkce_state', state)
    const challenge = generateCodeChallenge(verifier)
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: 'code',
      scope: SCOPE,
      redirect_uri: REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    })
    window.location.href = '/oauth2/authorize?' + params.toString()
  }, [])

  const handleCallback = useCallback(async (code: string, state: string): Promise<boolean> => {
    const savedState = sessionStorage.getItem('pkce_state')
    console.log('[auth] savedState:', savedState, 'received state:', state)
    if (state !== savedState) {
      console.error('[auth] state mismatch')
      return false
    }
    const verifier = sessionStorage.getItem('pkce_verifier')
    if (!verifier) {
      console.error('[auth] verifier not found in sessionStorage')
      return false
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    })

    const basicAuth = 'Basic ' + btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)
    console.log('[auth] token request client_id:', CLIENT_ID, 'has_secret:', !!CLIENT_SECRET)
    const resp = await fetch('/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth,
      },
      body: body.toString(),
    })

    console.log('[auth] token response status:', resp.status)

    if (!resp.ok) {
      const errText = await resp.text()
      console.error('[auth] token request failed:', resp.status, errText)
      clearTokens()
      sessionStorage.removeItem('pkce_verifier')
      sessionStorage.removeItem('pkce_state')
      setAuth({ accessToken: null, refreshToken: null, isAuthenticated: false })
      return false
    }

    const data: TokenResponse = await resp.json()
    console.log('[auth] token received, access_token length:', data.access_token?.length)
    saveTokens(data.access_token, data.refresh_token)
    sessionStorage.removeItem('pkce_verifier')
    sessionStorage.removeItem('pkce_state')
    setAuth({ accessToken: data.access_token, refreshToken: data.refresh_token || null, isAuthenticated: true })
    return true
  }, [])

  const logout = useCallback(() => {
    clearTokens()
    setAuth({ accessToken: null, refreshToken: null, isAuthenticated: false })
  }, [])

  return (
    <AuthContext.Provider value={{ ...auth, login, logout, handleCallback }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
