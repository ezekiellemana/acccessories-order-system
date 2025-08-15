// src/components/Layout.jsx
import React, { useEffect } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import Navbar from './Navbar';
import Footer from './Footer';
import Banner from './Banner';
import useAuthStore from '../store/useAuthStore';

export default function Layout() {
  const location = useLocation();
  const sessionExpired = useAuthStore((s) => s.sessionExpired);
  const setSessionExpired = useAuthStore((s) => s.setSessionExpired);

  // Scroll to top on route change
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, [location.pathname]);

  return (
    <>
      {/* Skip-to-content link for accessibility */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 bg-accent-500 text-white px-2 py-1 rounded"
      >
        Skip to content
      </a>

      {sessionExpired && (
        <Banner
          message="You were logged out for inactivity."
          onClose={() => setSessionExpired(false)}
        />
      )}

      <div className="flex flex-col min-h-screen bg-neutral-50 dark:bg-neutral-900 text-neutral-800 dark:text-neutral-200 transition-colors">
        {/* Sticky navbar */}
        <header className="sticky top-0 z-50 bg-neutral-50 dark:bg-neutral-900 shadow-sm">
          <Navbar />
        </header>

        {/* Main content area */}
        <main
          id="main-content"
          className="flex-grow container max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 py-8"
        >
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={location.pathname}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.4, ease: 'easeInOut' }}
            >
              <Outlet />
            </motion.div>
          </AnimatePresence>
        </main>

        {/* Footer */}
        <footer className="bg-neutral-100 dark:bg-neutral-800">
          <Footer />
        </footer>
      </div>
    </>
  );
}
