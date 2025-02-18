'use client'

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
      // Error is already handled by useAuth hook
      console.error('Failed to submit email:', err)
    }
  }

  const handleVerificationSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!verificationCode) return

    try {
      await verifyCode(verificationCode)
    } catch (err) {
      // Error is already handled by useAuth hook
      console.error('Failed to verify code:', err)
    }
  }

  if (isLoading) {
    return <div>Loading...</div>
  }

  return (
    <div className="w-full max-w-md mx-auto p-6">
      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}
      
      {step === 'email' ? (
        <form onSubmit={handleEmailSubmit} className="space-y-4">
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700">
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
              required
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            {mode === 'login' ? 'Login' : 'Register'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleVerificationSubmit} className="space-y-4">
          <div>
            <label htmlFor="code" className="block text-sm font-medium text-gray-700">
              Verification Code
            </label>
            <input
              id="code"
              type="text"
              value={verificationCode}
              onChange={(e) => setVerificationCode(e.target.value)}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
              required
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            Verify Code
          </button>
        </form>
      )}
    </div>
  )
}
