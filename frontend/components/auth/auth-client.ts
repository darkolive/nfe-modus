import { AuthResponse, APIError } from '@/types/auth'

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

    const data = await response.json()

    if (!response.ok) {
      const error = data as APIError
      throw new Error(error.message || `HTTP error! status: ${response.status}`)
    }

    return data as T
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
