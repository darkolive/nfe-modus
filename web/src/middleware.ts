import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { jwtVerify } from "jose";

// Define protected routes that require authentication
const protectedRoutes = ["/dashboard", "/profile", "/settings"];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Check if the route is protected
  const isProtectedRoute = protectedRoutes.some(
    (route) => pathname === route || pathname.startsWith(`${route}/`)
  );

  // If it's not a protected route, allow access
  if (!isProtectedRoute) {
    return NextResponse.next();
  }

  // Get the session cookie
  const sessionCookie = request.cookies.get("session")?.value;

  // If there's no session cookie, redirect to sign in
  if (!sessionCookie) {
    const signInUrl = new URL("/auth/signin", request.url);
    signInUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(signInUrl);
  }

  try {
    // Verify the JWT
    const secret = new TextEncoder().encode(
      process.env.JWT_SECRET || "your-secret-key-at-least-32-characters-long"
    );

    await jwtVerify(sessionCookie, secret);

    // If verification succeeds, allow access
    return NextResponse.next();
  } catch (error) {
    // If verification fails, redirect to sign in
    console.error("JWT verification failed:", error);
    const signInUrl = new URL("/auth/signin", request.url);
    signInUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(signInUrl);
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    "/((?!_next/static|_next/image|favicon.ico|public).*)",
  ],
};
