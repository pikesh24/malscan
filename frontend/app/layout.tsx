import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { NativeIntentBridge } from "../components/NativeIntentBridge";
import { UpdaterProvider } from "../components/UpdaterProvider";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Malscan — Threat Visualized",
  description:
    "Static analysis, threat intelligence and infrastructure mapping for files and URLs.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <UpdaterProvider>
          <NativeIntentBridge />
          {children}
        </UpdaterProvider>
      </body>
    </html>
  );
}
