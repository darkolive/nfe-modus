'use client'

import { AuthResponse, APIError } from '@/types/auth'

const isValidEmail = (email: string): boolean => {
  if (!email || typeof email !== 'string') return false
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email.trim())
}

export class AuthClient {
  private baseUrl: string

  constructor() {
    this.baseUrl = '/api/auth'
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
      })

      const data = await response.json()

      if (!response.ok) {
        const error = data as APIError
        throw new Error(error.message || `HTTP error! status: ${response.status}`)
      }

      return data as T
    } catch (error) {
      if (error instanceof Error) {
        throw error
      }
      throw new Error('An unexpected error occurred')
    }
  }

  async startAuthentication(email: string): Promise<AuthResponse> {
    if (!isValidEmail(email)) {
      throw new Error('Please enter a valid email address')
    }
    return this.request<AuthResponse>('/login', {
      method: 'POST',
      body: JSON.stringify({ email: email.trim() }),
    })
  }

  async startRegistration(email: string): Promise<AuthResponse> {
    if (!isValidEmail(email)) {
      throw new Error('Please enter a valid email address')
    }
    return this.request<AuthResponse>('/register', {
      method: 'POST',
      body: JSON.stringify({ email: email.trim() }),
    })
  }

  async verifyCode(code: string): Promise<AuthResponse> {
    if (!code || typeof code !== 'string' || code.length < 6) {
      throw new Error('Please enter a valid verification code')
    }
    return this.request<AuthResponse>('/verify', {
      method: 'POST',
      body: JSON.stringify({ code: code.trim() }),
    })
  }

  // WebAuthn methods
  async startWebAuthnRegistration(): Promise<AuthResponse> {
    return this.request<AuthResponse>('/webauthn/register/start', {
      method: 'POST',
    })
  }

  async finishWebAuthnRegistration(data: any): Promise<AuthResponse> {
    return this.request<AuthResponse>('/webauthn/register/finish', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async startWebAuthnAuthentication(): Promise<AuthResponse> {
    return this.request<AuthResponse>('/webauthn/authenticate/start', {
      method: 'POST',
    })
  }

  async finishWebAuthnAuthentication(data: any): Promise<AuthResponse> {
    return this.request<AuthResponse>('/webauthn/authenticate/finish', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }
}
