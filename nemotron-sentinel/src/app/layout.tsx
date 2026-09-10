import type { Metadata } from "next";
import "./globals.css";

import { Starfield } from "@/components/ui/Starfield";
import { LightSweep } from "@/components/ui/LightSweep";
import { GraphBackground } from "@/components/3d/GraphBackground";

export const metadata: Metadata = {
  title: "SheildMail | AI-Powered Email Threat Defense & Forensics",
  description: "Enterprise email threat defense, forensic inspection, and real-time neural threat telemetry powered by SheildMail",
  keywords: ["email security", "threat intelligence", "phishing detection", "forensic analysis", "AI defense", "cybersecurity", "SheildMail"],
  authors: [{ name: "SheildMail Enterprise Security" }],
  openGraph: {
    title: "SheildMail | AI-Powered Email Threat Defense",
    description: "Enterprise email threat detection and forensic intelligence platform",
    type: "website",
  },
};

export default function RootLayout({ children }: React.PropsWithChildren) {
  return (
    <html lang="en" className="h-full antialiased">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="min-h-full flex flex-col bg-black text-white relative">
        {/* Deep Space Cosmic Galaxy Nebula Background Layer */}
        <div
          className="fixed inset-0 pointer-events-none z-0 select-none"
          style={{
            backgroundColor: "#000000",
            backgroundImage: `
              radial-gradient(ellipse 70% 55% at 85% 15%, rgba(14, 40, 85, 0.35) 0%, transparent 65%),
              radial-gradient(ellipse 65% 50% at 15% 85%, rgba(55, 12, 28, 0.28) 0%, transparent 60%),
              radial-gradient(ellipse 90% 70% at 50% 40%, rgba(8, 14, 28, 0.65) 0%, rgba(0, 0, 0, 0.96) 85%)
            `,
            backgroundSize: "100% 100%, 100% 100%, 100% 100%",
            backgroundPosition: "center top, center top, center top",
            backgroundRepeat: "no-repeat, no-repeat, no-repeat",
          }}
          aria-hidden="true"
        />
        {/* Standalone 2D Canvas Starfield with Multi-Depth Parallax & Twinkling */}
        <Starfield starCount={220} showGrid={false} />
        <GraphBackground />
        {/* Subtle Diagonal Ambient Light Sweep Layer */}
        <LightSweep />
        <div className="relative z-10 flex-1 flex flex-col">
          {children}
        </div>
      </body>
    </html>
  );
}