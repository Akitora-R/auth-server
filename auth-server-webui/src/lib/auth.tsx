import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import type { TokenResponse } from '../types'

const CLIENT_ID = 'internal_admin_console'
// The client secret for the admin SPA. In production this is injected at build time.
const CLIENT_SECRET = '__ADMIN_CLIENT_SECRET__'
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

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return base64URLEncode(new Uint8Array(hash))
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
    generateCodeChallenge(verifier).then((challenge) => {
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
    })
  }, [])

  const handleCallback = useCallback(async (code: string, state: string): Promise<boolean> => {
    const savedState = sessionStorage.getItem('pkce_state')
    if (state !== savedState) return false
    const verifier = sessionStorage.getItem('pkce_verifier')
    if (!verifier) return false

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    })

    const basicAuth = 'Basic ' + btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)
    const resp = await fetch('/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth,
      },
      body: body.toString(),
    })

    if (!resp.ok) {
      clearTokens()
      sessionStorage.removeItem('pkce_verifier')
      sessionStorage.removeItem('pkce_state')
      setAuth({ accessToken: null, refreshToken: null, isAuthenticated: false })
      return false
    }

    const data: TokenResponse = await resp.json()
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
