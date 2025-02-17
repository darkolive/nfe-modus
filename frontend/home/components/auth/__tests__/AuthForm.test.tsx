import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AuthForm } from '../AuthForm'
import { useAuth } from '../../../auth/useAuth'
import { AuthResponse } from '../../../auth/types'

// Mock useAuth hook
jest.mock('../../../auth/useAuth', () => ({
  useAuth: jest.fn(() => ({
    isLoading: false,
    error: null,
    session: null,
    login: jest.fn(),
    register: jest.fn(),
    verifyCode: jest.fn(),
  })),
}))

describe('AuthForm', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    localStorage.clear()
  })

  it('renders login form by default', () => {
    render(<AuthForm mode="login" />)
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /continue/i })).toBeInTheDocument()
  })

  it('handles email submission', async () => {
    const mockLogin = jest.fn()
    const mockSession: AuthResponse = {
      needsVerification: true,
      session: {
        did: 'test-did',
        challenge: 'test-challenge',
        deviceId: 'test-device',
        userEmail: 'test@example.com',
      },
    }

    ;(useAuth as jest.Mock).mockImplementation(() => ({
      isLoading: false,
      error: null,
      session: null,
      login: mockLogin.mockResolvedValue(mockSession),
      register: jest.fn(),
      verifyCode: jest.fn(),
    }))

    render(<AuthForm mode="login" />)
    const emailInput = screen.getByLabelText(/email/i)
    const submitButton = screen.getByRole('button', { name: /continue/i })

    fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('test@example.com')
    })
  })

  it('validates email format', async () => {
    render(<AuthForm mode="login" />)
    
    const emailInput = screen.getByLabelText(/email/i)
    fireEvent.change(emailInput, { target: { value: 'invalid-email' } })
    
    const submitButton = screen.getByRole('button', { name: /continue/i })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(screen.getByText(/please enter a valid email/i)).toBeInTheDocument()
    })
  })

  it('handles code verification', async () => {
    const mockVerifyCode = jest.fn()
    ;(useAuth as jest.Mock).mockImplementation(() => ({
      isLoading: false,
      error: null,
      session: {
        needsVerification: true,
        session: {
          did: 'test-did',
          challenge: 'test-challenge',
          deviceId: 'test-device',
          userEmail: 'test@example.com',
        },
      },
      login: jest.fn(),
      register: jest.fn(),
      verifyCode: mockVerifyCode,
    }))

    render(<AuthForm mode="login" />)

    // Submit verification code
    const codeInput = await screen.findByLabelText(/verification code/i)
    fireEvent.change(codeInput, { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /verify/i }))

    await waitFor(() => {
      expect(mockVerifyCode).toHaveBeenCalledWith('123456')
    })
  })

  it('shows loading state', async () => {
    ;(useAuth as jest.Mock).mockImplementation(() => ({
      isLoading: true,
      error: null,
      session: null,
      login: jest.fn(),
      register: jest.fn(),
      verifyCode: jest.fn(),
    }))

    render(<AuthForm mode="login" />)
    expect(screen.getByText(/loading/i)).toBeInTheDocument()
  })

  it('shows error message', async () => {
    ;(useAuth as jest.Mock).mockImplementation(() => ({
      isLoading: false,
      error: 'Authentication failed',
      session: null,
      login: jest.fn(),
      register: jest.fn(),
      verifyCode: jest.fn(),
    }))

    render(<AuthForm mode="login" />)
    expect(screen.getByText(/authentication failed/i)).toBeInTheDocument()
  })
})
