'use client'

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
      setState({ ...state, isLoading: false, session: response })
    } catch (error) {
      setState({ 
        ...state, 
        isLoading: false, 
        error: error instanceof Error ? error.message : 'Failed to login'
      })
      throw error
    }
  }

  const register = async (email: string) => {
    setState({ ...state, isLoading: true, error: null })
    try {
      const response = await authClient.startRegistration(email)
      setState({ ...state, isLoading: false, session: response })
    } catch (error) {
      setState({ 
        ...state, 
        isLoading: false, 
        error: error instanceof Error ? error.message : 'Failed to register'
      })
      throw error
    }
  }

  const verifyCode = async (code: string) => {
    setState({ ...state, isLoading: true, error: null })
    try {
      const response = await authClient.verifyCode(code)
      setState({ ...state, isLoading: false, session: response })
    } catch (error) {
      setState({ 
        ...state, 
        isLoading: false, 
        error: error instanceof Error ? error.message : 'Failed to verify code'
      })
      throw error
    }
  }

  return {
    login,
    register,
    verifyCode,
    isLoading: state.isLoading,
    error: state.error,
    session: state.session,
  }
}
