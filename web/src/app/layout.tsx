import type { Metadata } from "next";
import { Header } from "@/components/header";
import "./globals.css";

export const metadata: Metadata = {
  title: "NFE Modus",
  description: "NFE Modus",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" data-theme="modern">
      <body>
        <Header />
        {children}
      </body>
    </html>
  );
}
