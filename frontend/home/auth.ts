import NextAuth from 'next-auth';
import { JWT } from 'next-auth/jwt';

interface User {
  id: string;
  email: string;
  name?: string;
}

declare module 'next-auth' {
  interface Session {
    user: User;
    token: string;
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    userId: string;
    email: string;
    token: string;
  }
}

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth({
  pages: {
    signIn: '/',  // Using our custom sign-in page
    error: '/auth/error',
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.userId = user.id;
        token.email = user.email;
      }
      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user = {
          id: token.userId,
          email: token.email,
        };
        session.token = token.token;
      }
      return session;
    },
  },
  providers: [],  // We'll add our custom provider later
});
