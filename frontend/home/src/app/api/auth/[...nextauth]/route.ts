import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';

const handler = NextAuth({
  providers: [
    CredentialsProvider({
      id: 'credentials',
      name: 'Credentials',
      credentials: {
        token: { type: 'text' },
        user: { type: 'text' },
      },
      async authorize(credentials) {
        if (!credentials?.token || !credentials?.user) {
          return null;
        }

        const user = JSON.parse(credentials.user);
        
        return {
          id: user.id,
          email: user.email,
          token: credentials.token,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.userId = user.id;
        token.email = user.email;
        token.token = user.token;
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
  pages: {
    signIn: '/',
    error: '/auth/error',
  },
});

export { handler as GET, handler as POST };
