import { useState, useEffect } from 'react'
import { authClient } from './api-client'
import { AuthResponse, User } from './types'

interface AuthState {
  isLoading: boolean
  error: string | null
  session: AuthResponse | null
  user: User | null
}

export function useAuth() {
  const [state, setState] = useState<AuthState>({
    isLoading: false,
    error: null,
    session: null,
    user: null,
  })

  useEffect(() => {
    const session = localStorage.getItem('auth_session')
    if (session) {
      try {
        const { user } = JSON.parse(session)
        setState(prev => ({
          ...prev,
          user,
        }))
      } catch {
        setState(prev => ({ ...prev }))
      }
    }
  }, [])

  const register = async (email: string) => {
    try {
      setState(prev => ({ ...prev, isLoading: true, error: null }))
      const response = await authClient.startRegistration(email)

      setState(prev => ({
        ...prev,
        session: response,
        user: {
          email,
          deviceId: response.session.deviceId,
          did: response.session.did,
        },
      }))

      localStorage.setItem('auth_session', JSON.stringify({ user: { email } }))
    } catch (error) {
      setState(prev => ({
        ...prev,
        error: 'Failed to start registration',
      }))
      throw error
    } finally {
      setState(s => ({ ...s, isLoading: false }))
    }
  }

  const login = async (email: string) => {
    try {
      setState(prev => ({ ...prev, isLoading: true, error: null }))
      const response = await authClient.startAuthentication(email)

      setState(prev => ({
        ...prev,
        session: response,
        user: {
          email,
          deviceId: response.session.deviceId,
          did: response.session.did,
        },
      }))

      localStorage.setItem('auth_session', JSON.stringify({ user: { email } }))
    } catch (error) {
      setState(prev => ({
        ...prev,
        error: 'Failed to start authentication',
      }))
      throw error
    } finally {
      setState(s => ({ ...s, isLoading: false }))
    }
  }

  const logout = () => {
    localStorage.removeItem('auth_session')
    setState({
      isLoading: false,
      error: null,
      session: null,
      user: null,
    })
  }

  const verifyCode = async (code: string) => {
    try {
      setState(prev => ({ ...prev, isLoading: true, error: null }))
      const response = await authClient.verifyCode(code)

      setState(prev => ({
        ...prev,
        session: response,
        user: prev.user ? {
          ...prev.user,
          deviceId: response.session.deviceId,
          did: response.session.did,
        } : null,
      }))
    } catch (error) {
      setState(prev => ({
        ...prev,
        error: 'Failed to verify code',
      }))
      throw error
    } finally {
      setState(s => ({ ...s, isLoading: false }))
    }
  }

  return {
    ...state,
    register,
    login,
    logout,
    verifyCode,
  }
}
