import { NextResponse } from 'next/server'

export async function POST(req: Request) {
  try {
    const body = await req.json()
    
    if (!body.email) {
      return NextResponse.json(
        { error: 'Email is required' },
        { status: 400 }
      )
    }

    console.log('Starting registration process for email:', body.email)
    
    const response = await fetch('http://localhost:8686/api/auth/otp/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: body.email.trim().toLowerCase()
      }),
    })

    const data = await response.json()
    console.log('Backend response:', data)

    if (!response.ok) {
      return NextResponse.json(
        { 
          error: data.message || 'Failed to start registration process',
          code: data.code
        },
        { status: response.status }
      )
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('Registration error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to start registration process' },
      { status: 500 }
    )
  }
}
