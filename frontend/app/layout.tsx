import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import '../styles/globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'AdversarialShield - AI Security Platform',
  description: 'Multimodal AI Security Testing & Guardrails Platform',
  keywords: ['AI Security', 'LLM Security', 'Adversarial Testing', 'Guardrails', 'Threat Detection'],
  authors: [{ name: 'AdversarialShield Team' }],
  icons: {
    icon: '/favicon.ico',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        <div className="relative z-10">
          {children}
        </div>
      </body>
    </html>
  )
}
