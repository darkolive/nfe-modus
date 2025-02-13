import { auth } from './auth';
 
export default auth((req) => {
  // Protect all routes except public ones
  const publicPaths = ['/', '/auth/error'];
  const isPublicPath = publicPaths.some(path => 
    req.nextUrl.pathname.startsWith(path)
  );

  if (isPublicPath) {
    return null;
  }

  // Check if user is authenticated
  const isAuthenticated = !!req.auth;
  
  if (!isAuthenticated) {
    return Response.redirect(new URL('/', req.nextUrl.origin));
  }

  return null;
})

// Optionally configure middleware matcher
export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
}
