// src/pages/AdminDashboard.jsx
import React, { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import useAuthStore from '../store/useAuthStore';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'react-toastify';
import {
  User,
  FilePlus,
  BarChart2,
  Tag,
  ShoppingCart,
  LogOut,
  Menu as MenuIcon,
  X as CloseIcon,
} from 'lucide-react';
import Breadcrumbs from '../components/Breadcrumbs';

const LINKS = [
  { to: '/admin/users', label: 'Users', icon: <User size={20} /> },
  { to: '/admin/products', label: 'Products', icon: <FilePlus size={20} /> },
  { to: '/admin/categories', label: 'Categories', icon: <Tag size={20} /> },
  { to: '/admin/orders', label: 'Orders', icon: <ShoppingCart size={20} /> },
  { to: '/admin/reviews', label: 'Reviews', icon: <FilePlus size={20} /> },
  { to: '/admin/analytics/charts', label: 'Analytics', icon: <BarChart2 size={20} /> },
];

export default function AdminDashboard() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const navigate = useNavigate();
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Redirect non-admins
  useEffect(() => {
    if (user && !user.isAdmin) {
      toast.error('Admin access only.');
      navigate('/login', { replace: true });
    } else if (user === null) {
      navigate('/login', { replace: true });
    }
  }, [user, navigate]);

  const handleLogout = () => {
    logout();
    navigate('/', { replace: true });
  };

  // Sidebar content
  const Sidebar = () => (
    <div className="h-full flex flex-col bg-primary-700 text-white w-64">
      <div className="flex items-center justify-between px-6 py-4 border-b border-primary-800">
        <h1 className="text-xl font-bold">aStore Admin</h1>
        <button className="md:hidden p-1" onClick={() => setDrawerOpen(false)}>
          <CloseIcon size={20} />
        </button>
      </div>
      <div className="flex-1 overflow-auto px-4 py-6 space-y-2">
        {LINKS.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            onClick={() => setDrawerOpen(false)}
            className={({ isActive }) =>
              `flex items-center px-4 py-2 rounded-lg transition ${
                isActive ? 'bg-primary-800' : 'hover:bg-primary-600'
              }`
            }
          >
            <span className="mr-3">{icon}</span>
            <span>{label}</span>
          </NavLink>
        ))}
      </div>
      <div className="px-6 py-4 border-t border-primary-800 text-sm">
        Signed in as <strong>{user?.name}</strong>
      </div>
      <div className="px-6 py-4">
        <button
          onClick={handleLogout}
          className="w-full bg-secondary hover:bg-secondary-600 text-white py-2 rounded-2xl transition"
        >
          <LogOut size={18} className="inline-block mr-2" />
          Logout
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-neutral-50 dark:bg-neutral-900">
      {/* Mobile header */}
      <header className="md:hidden flex items-center justify-between bg-white dark:bg-neutral-800 border-b border-neutral-200 dark:border-neutral-700 px-4 py-3">
        <button onClick={() => setDrawerOpen(true)} className="p-1 text-primary-600">
          <MenuIcon size={24} />
        </button>
        <h2 className="text-lg font-semibold">Admin Dashboard</h2>
        <button onClick={handleLogout} className="p-1 text-primary-600">
          <LogOut size={24} />
        </button>
      </header>

      <div className="flex">
        {/* Mobile drawer */}
        <AnimatePresence>
          {drawerOpen && (
            <motion.div
              className="fixed inset-0 z-40 flex"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <div
                className="fixed inset-0 bg-black bg-opacity-50"
                onClick={() => setDrawerOpen(false)}
              />
              <motion.div
                className="relative"
                initial={{ x: '-100%' }}
                animate={{ x: 0 }}
                exit={{ x: '-100%' }}
                transition={{ type: 'tween' }}
              >
                <Sidebar />
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Desktop sidebar */}
        <aside className="hidden md:flex">
          <Sidebar />
        </aside>

        {/* Main content */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Desktop header */}
          <header className="hidden md:flex items-center justify-between bg-white dark:bg-neutral-800 border-b border-neutral-200 dark:border-neutral-700 px-6 py-4">
            <h2 className="text-2xl font-semibold text-neutral-800 dark:text-neutral-100">
              Admin Dashboard
            </h2>
            <Breadcrumbs />
          </header>

          <main className="flex-1 overflow-auto p-4 md:p-6 lg:p-8">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.3 }}
              className="space-y-6"
            >
              <Outlet />
            </motion.div>
          </main>
        </div>
      </div>
    </div>
  );
}
