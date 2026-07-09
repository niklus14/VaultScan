import type { Metadata } from "next";
import { Space_Grotesk, Ubuntu_Mono } from "next/font/google";
import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space-grotesk",
  subsets: ["latin"],
});

const ubuntuMono = Ubuntu_Mono({
  variable: "--font-ubuntu-mono",
  weight: ["400", "700"],
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "V.A.U.L.T.S.C.A.N. — Cloud Security Posture Management",
  description:
    "Enterprise SOC command console for cloud security posture management, vulnerability tracking, and compliance monitoring.",
  generator: "v0.app",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark bg-background">
      <body className={`${spaceGrotesk.variable} ${ubuntuMono.variable}`}>
        {children}
      </body>
    </html>
  );
}
