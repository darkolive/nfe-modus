import React, { useState, useEffect } from 'react'
import { useAuth } from '@/hooks/useAuth'

interface AuthFormProps {
  mode: 'login' | 'register'
}

export const AuthForm: React.FC<AuthFormProps> = ({ mode }) => {
  const [email, setEmail] = useState('')
  const [verificationCode, setVerificationCode] = useState('')
  const [step, setStep] = useState<'email' | 'verify'>('email')
  const { login, register, verifyCode, isLoading, error, session } = useAuth()

  useEffect(() => {
    if (session?.needsVerification) {
      setStep('verify')
    }
  }, [session])

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email) return

    try {
      if (mode === 'login') {
        await login(email)
      } else {
        await register(email)
      }
    } catch (err) {
      console.error('Failed to submit email:', err)
    }
  }

  const handleVerificationSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!verificationCode) return

    try {
      await verifyCode(verificationCode)
    } catch (err) {
      console.error('Failed to verify code:', err)
    }
  }

  if (isLoading) {
    return React.createElement('div', null, 'Loading...')
  }

  if (error) {
    return React.createElement('div', { className: 'error' }, error)
  }

  return React.createElement('div', { className: 'auth-form' },
    step === 'email' ?
      React.createElement('form', { onSubmit: handleEmailSubmit },
        React.createElement('label', { htmlFor: 'email' }, 'Email'),
        React.createElement('input', {
          id: 'email',
          type: 'email',
          value: email,
          onChange: (e) => setEmail(e.target.value),
          placeholder: 'Enter your email',
          required: true,
        }),
        React.createElement('button', { type: 'submit' }, 'Continue')
      ) :
      React.createElement('form', { onSubmit: handleVerificationSubmit },
        React.createElement('label', { htmlFor: 'code' }, 'Verification Code'),
        React.createElement('input', {
          id: 'code',
          type: 'text',
          value: verificationCode,
          onChange: (e) => setVerificationCode(e.target.value),
          placeholder: 'Enter verification code',
          pattern: '[0-9]{6}',
          title: 'Please enter a 6-digit code',
          required: true,
        }),
        React.createElement('button', { type: 'submit' }, 'Verify')
      )
  )
}
