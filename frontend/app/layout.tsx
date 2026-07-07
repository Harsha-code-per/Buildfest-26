import type { Metadata } from "next";
import { Fraunces, Inter } from "next/font/google";
import Hero3D from "@/components/Hero3D";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const fraunces = Fraunces({
  subsets: ["latin"],
  style: ["italic", "normal"],
  variable: "--font-fraunces",
});

export const metadata: Metadata = {
  title: "RiskSense — Decide, don't just score",
  description:
    "CVE triage that gives you a decision, not a number: transparent SSVC (Act / Attend / Track) from CVSS + EPSS + CISA KEV.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${fraunces.variable}`}>
      <body className="antialiased">
        {/* Persistent cinematic background stack behind all content. */}
        <Hero3D />
        <div id="vig" />
        <div id="grain" />
        {children}
      </body>
    </html>
  );
}
