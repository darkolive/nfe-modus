import { NextResponse } from 'next/server'

export async function POST(req: Request) {
  try {
    const body = await req.json()
    
    if (!body.code) {
      return NextResponse.json(
        { error: 'Verification code is required' },
        { status: 400 }
      )
    }

    console.log('Starting verification process')
    
    const response = await fetch('http://localhost:8686/api/auth/otp/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code: body.code.trim()
      }),
    })

    const data = await response.json()
    console.log('Backend response:', data)

    if (!response.ok) {
      return NextResponse.json(
        { 
          error: data.message || 'Failed to verify code',
          code: data.code
        },
        { status: response.status }
      )
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('Verification error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to verify code' },
      { status: 500 }
    )
  }
}
