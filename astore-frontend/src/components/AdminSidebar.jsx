import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { User, FilePlus, BarChart2, Tag, ShoppingCart, LogOut, Menu, X } from 'lucide-react';
import useAuthStore from '../store/useAuthStore';
import { Button } from '@/components/ui/button';

const LINKS = [
  { to: '/admin/users', label: 'Users', icon: <User size={20} /> },
  { to: '/admin/products', label: 'Products', icon: <FilePlus size={20} /> },
  { to: '/admin/categories', label: 'Categories', icon: <Tag size={20} /> },
  { to: '/admin/orders', label: 'Orders', icon: <ShoppingCart size={20} /> },
  { to: '/admin/reviews', label: 'Reviews', icon: <FilePlus size={20} /> },
  { to: '/admin/analytics/charts', label: 'Analytics', icon: <BarChart2 size={20} /> },
];

export default function AdminSidebar() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const [isOpen, setIsOpen] = useState(false);

  const handleLinkClick = () => {
    // auto-close on mobile when a link is clicked
    setIsOpen(false);
  };

  return (
    <>
      {/* Mobile hamburger */}
      <button
        className="md:hidden fixed top-4 left-4 z-50 p-2 bg-primary-700 text-white rounded-lg"
        onClick={() => setIsOpen(true)}
      >
        <Menu size={24} />
      </button>

      {/* Overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 z-40"
          onClick={() => setIsOpen(false)}
        />
      )}

      <aside
        className={`${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        } md:translate-x-0 fixed md:static top-0 left-0 z-50 h-full w-64 bg-primary-700 text-white shadow-navbar transform transition-transform duration-200 ease-in-out`}
      >
        <div className="px-6 py-4 border-b border-primary-800 flex items-center justify-between">
          <h1 className="text-xl font-bold">eStore Admin</h1>
          <button
            className="md:hidden p-1"
            onClick={() => setIsOpen(false)}
          >
            <X size={20} />
          </button>
        </div>
        <nav className="px-4 py-6 space-y-2 overflow-y-auto">
          {LINKS.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              onClick={handleLinkClick}
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
        </nav>
        <div className="mt-auto px-6 py-4 border-t border-primary-800">
          <p className="text-sm">Signed in as</p>
          <p className="font-medium">{user?.name}</p>
          <Button
            variant="default"
            className="mt-3 w-full flex items-center justify-center"
            onClick={() => {
              logout();
            }}
          >
            <LogOut size={18} className="mr-2" /> Logout
          </Button>
        </div>
      </aside>
    </>
  );
}
