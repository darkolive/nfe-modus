import { useState } from 'react'
import { AuthClient } from '@/components/auth/auth-client'
import { AuthResponse } from '@/types/auth'

interface AuthState {
  isLoading: boolean
  error: string | null
  session: AuthResponse | null
}

export function useAuth() {
  const [state, setState] = useState<AuthState>({
    isLoading: false,
    error: null,
    session: null,
  })

  const authClient = new AuthClient()

  const login = async (email: string) => {
    setState({ ...state, isLoading: true, error: null })
    try {
      const response = await authClient.startAuthentication(email)
      setState({ ...state, session: response })
    } catch (err) {
      setState({ ...state, error: 'Failed to start authentication' })
      throw err
    } finally {
      setState((s) => ({ ...s, isLoading: false }))
    }
  }

  const register = async (email: string) => {
    setState({ ...state, isLoading: true, error: null })
    try {
      const response = await authClient.startRegistration(email)
      setState({ ...state, session: response })
    } catch (err) {
      setState({ ...state, error: 'Failed to start registration' })
      throw err
    } finally {
      setState((s) => ({ ...s, isLoading: false }))
    }
  }

  const verifyCode = async (code: string) => {
    setState({ ...state, isLoading: true, error: null })
    try {
      const response = await authClient.verifyCode(code)
      setState({ ...state, session: response })
    } catch (err) {
      setState({ ...state, error: 'Failed to verify code' })
      throw err
    } finally {
      setState((s) => ({ ...s, isLoading: false }))
    }
  }

  return {
    ...state,
    login,
    register,
    verifyCode,
  }
}
