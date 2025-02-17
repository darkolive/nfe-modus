import React from 'react'
import { AuthForm } from '@/components/auth/AuthForm'

export default function Home() {
  return (
    <main>
      <AuthForm mode="login" />
    </main>
  )
}
