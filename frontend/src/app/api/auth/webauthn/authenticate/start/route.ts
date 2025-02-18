import { NextResponse } from 'next/server'

export async function POST(req: Request) {
  try {
    const body = await req.json()
    
    const response = await fetch('http://localhost:8686/api/auth/webauthn/authenticate/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })

    if (!response.ok) {
      throw new Error(`Backend responded with status: ${response.status}`)
    }

    const data = await response.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('WebAuthn authentication start error:', error)
    return NextResponse.json(
      { error: 'Failed to start WebAuthn authentication' },
      { status: 500 }
    )
  }
}
