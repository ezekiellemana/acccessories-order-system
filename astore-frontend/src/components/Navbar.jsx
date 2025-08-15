// src/components/Navbar.jsx

import React, { useEffect, useState } from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import {
  Menu as MenuIcon,
  X as CloseIcon,
  LogOut,
  ShoppingCart,
  Sun,
  Moon,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import api from '../services/api';
import useAuthStore from '../store/useAuthStore';
import useCartStore from '../store/useCartStore';
import useThemeStore from '../store/useThemeStore';
import LogoutConfirmationModal from './LogoutConfirmationModal';

export default function Navbar() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const cartItems = useCartStore((s) => s.items);
  const theme = useThemeStore((s) => s.theme);
  const toggleTheme = useThemeStore((s) => s.toggle);
  const navigate = useNavigate();

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [categories, setCategories] = useState([]);

  // Load categories from backend
  useEffect(() => {
    (async () => {
      try {
        const { data } = await api.get('/api/categories');
        setCategories(Array.isArray(data) ? data : []);
      } catch (err) {
        console.error('Could not load categories', err);
      }
    })();
  }, []);

  // Prevent back-nav when user is logged in
  useEffect(() => {
    if (!user) return;
    window.history.pushState(null, '', window.location.href);
    const handler = (e) => {
      e.preventDefault();
      setConfirmOpen(true);
    };
    window.addEventListener('popstate', handler);
    return () => window.removeEventListener('popstate', handler);
  }, [user]);

  const triggerLogout = () => setConfirmOpen(true);
  const onConfirmLogout = () => {
    setConfirmOpen(false);
    logout();
    navigate('/');
  };
  const onCancelLogout = () => {
    setConfirmOpen(false);
    window.history.pushState(null, '', window.location.href);
  };

  const goToCategory = (catId) => {
    navigate(`/products?category=${catId}`);
    setDrawerOpen(false);
  };

  return (
    <>
      <motion.nav
        initial={{ y: -50, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.5 }}
        className="fixed inset-x-0 top-0 z-50 bg-gradient-to-r from-primary-700 to-primary-500 shadow-navbar text-white"
      >
        <div className="max-w-7xl mx-auto flex items-center justify-between h-16 px-4 sm:px-6 lg:px-8">
          {/* Logo */}
          <Link to="/" className="text-2xl font-extrabold hover:opacity-90 transition-colors">
            <span className="text-accent-300">a</span>Store
          </Link>

          {/* Desktop Menu */}
          <div className="hidden md:flex items-center space-x-6">
            <NavLink
              to="/"
              className={({ isActive }) =>
                `px-3 py-1 rounded-md ${
                  isActive
                    ? 'bg-accent-300 text-primary-900 font-semibold'
                    : 'hover:bg-primary-600'
                }`
              }
            >
              Home
            </NavLink>

            {/* Products Dropdown */}
            <div className="relative group">
              <button className="flex items-center px-3 py-1 rounded-md hover:bg-primary-600 transition-colors">
                Products
                <svg className="ml-1 w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path d="M19 9l-7 7-7-7" strokeWidth="2" strokeLinecap="round" />
                </svg>
              </button>
              <div className="absolute left-0 mt-2 w-48 bg-primary-600 text-white rounded-lg shadow-lg opacity-0 group-hover:opacity-100 pointer-events-none group-hover:pointer-events-auto transition-opacity">
                {categories.map((cat) => (
                  <button
                    key={cat._id}
                    onClick={() => goToCategory(cat._id)}
                    className="w-full text-left px-4 py-2 hover:bg-primary-700 transition-colors"
                  >
                    {cat.name}
                  </button>
                ))}
              </div>
            </div>

            <NavLink
              to="/cart"
              className={({ isActive }) =>
                `flex items-center px-3 py-1 rounded-md ${
                  isActive
                    ? 'bg-accent-300 text-primary-900 font-semibold'
                    : 'hover:bg-primary-600'
                }`
              }
            >
              <ShoppingCart size={18} className="mr-1" /> Cart
              {cartItems.length > 0 && (
                <span className="ml-1 text-xs bg-accent-300 text-primary-900 rounded-full px-2">
                  {cartItems.length}
                </span>
              )}
            </NavLink>

            <button
              onClick={toggleTheme}
              className="p-2 rounded-md hover:bg-primary-600 transition-colors"
              aria-label="Toggle theme"
            >
              {theme === 'light' ? <Moon size={18} /> : <Sun size={18} />}
            </button>

            {user ? (
              <button
                onClick={triggerLogout}
                className="flex items-center px-3 py-1 rounded-md hover:bg-primary-600 transition-colors"
              >
                <LogOut size={18} className="mr-1" /> Logout
              </button>
            ) : (
              <>
                <NavLink to="/login" className="px-3 py-1 rounded-md hover:bg-primary-600 transition-colors">
                  Log In
                </NavLink>
                <NavLink to="/signup" className="px-3 py-1 rounded-md hover:bg-primary-600 transition-colors">
                  Sign Up
                </NavLink>
              </>
            )}
          </div>

          {/* Mobile Toggle */}
          <button
            onClick={() => setDrawerOpen((o) => !o)}
            className="md:hidden p-2 rounded-md hover:bg-primary-600 transition-colors"
            aria-label="Toggle menu"
          >
            {drawerOpen ? <CloseIcon size={24} /> : <MenuIcon size={24} />}
          </button>
        </div>

        {/* Mobile Drawer */}
        <AnimatePresence>
          {drawerOpen && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.25 }}
              className="md:hidden bg-gradient-to-r from-primary-700 to-primary-500 text-white overflow-hidden"
            >
              <div className="px-4 py-4 space-y-2">
                <NavLink
                  to="/"
                  onClick={() => setDrawerOpen(false)}
                  className="block px-3 py-2 rounded-md hover:bg-primary-600 transition-colors"
                >
                  Home
                </NavLink>
                <details className="group">
                  <summary className="px-3 py-2 rounded-md hover:bg-primary-600 cursor-pointer transition-colors">
                    Products
                  </summary>
                  <div className="pl-4 mt-1 space-y-1">
                    {categories.map((cat) => (
                      <button
                        key={cat._id}
                        onClick={() => goToCategory(cat._id)}
                        className="block px-3 py-1 rounded-md hover:bg-primary-600 transition-colors w-full text-left"
                      >
                        {cat.name}
                      </button>
                    ))}
                  </div>
                </details>
                <NavLink
                  to="/cart"
                  onClick={() => setDrawerOpen(false)}
                  className="block px-3 py-2 rounded-md hover:bg-primary-600 transition-colors"
                >
                  Cart
                </NavLink>
                {user ? (
                  <button
                    onClick={() => {
                      setDrawerOpen(false);
                      triggerLogout();
                    }}
                    className="w-full text-left px-3 py-2 rounded-md hover:bg-primary-600 transition-colors"
                  >
                    Logout
                  </button>
                ) : (
                  <>
                    <NavLink
                      to="/login"
                      onClick={() => setDrawerOpen(false)}
                      className="block px-3 py-2 rounded-md hover:bg-primary-600 transition-colors"
                    >
                      Log In
                    </NavLink>
                    <NavLink
                      to="/signup"
                      onClick={() => setDrawerOpen(false)}
                      className="block px-3 py-2 rounded-md hover:bg-primary-600 transition-colors"
                    >
                      Sign Up
                    </NavLink>
                  </>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.nav>

      <LogoutConfirmationModal
        open={confirmOpen}
        onConfirm={onConfirmLogout}
        onCancel={onCancelLogout}
      />
    </>
  );
}
