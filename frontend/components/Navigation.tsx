'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export default function Navigation() {
  const pathname = usePathname();

  const navItems = [
    { href: '/', label: 'Home', icon: '🏠' },
    { href: '/redteam', label: 'Red Team', icon: '🎯' },
    { href: '/guardrails', label: 'Guardrails', icon: '🛡️' },
    { href: '/scanner', label: 'Scanner', icon: '🔍' },
  ];

  return (
    <nav className="bg-gray-900/90 backdrop-blur-lg border-b border-purple-500/20 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link href="/" className="flex items-center space-x-3">
            <div className="text-2xl">🛡️</div>
            <div>
              <div className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-600">
                AdversarialShield
              </div>
              <div className="text-xs text-gray-400">AI Security Platform</div>
            </div>
          </Link>

          {/* Navigation Links */}
          <div className="flex space-x-1">
            {navItems.map((item) => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all ${
                    isActive
                      ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                      : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
                  }`}
                >
                  <span>{item.icon}</span>
                  <span className="font-medium">{item.label}</span>
                </Link>
              );
            })}
          </div>

          {/* Status Indicator */}
          <div className="flex items-center space-x-2">
            <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse"></div>
            <span className="text-xs text-gray-400">Online</span>
          </div>
        </div>
      </div>
    </nav>
  );
}
