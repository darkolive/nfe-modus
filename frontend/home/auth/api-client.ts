import { AuthResponse } from './types'

export class AuthClient {
  private baseUrl: string

  constructor() {
    this.baseUrl = process.env.NEXT_PUBLIC_API_URL || '/api/auth'
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    })

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }

    return response.json()
  }

  async startAuthentication(email: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('/start-auth', {
      method: 'POST',
      body: JSON.stringify({ email }),
    })
  }

  async startRegistration(email: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('/start-registration', {
      method: 'POST',
      body: JSON.stringify({ email }),
    })
  }

  async verifyCode(code: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('/verify-code', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
  }
}

// Create and export singleton instance
export const authClient = new AuthClient()
