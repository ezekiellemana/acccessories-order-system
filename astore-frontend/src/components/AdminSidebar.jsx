import React, { useState, useEffect } from "react";
import { NavLink } from "react-router-dom";
import {
  User,
  FilePlus,
  BarChart2,
  Tag,
  ShoppingCart,
  LogOut,
  Menu,
  X,
  Star,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import useAuthStore from "../store/useAuthStore";
import { Button } from "@/components/ui/button";

const LINKS = [
  { to: "/admin/users", label: "Users", icon: <User size={20} /> },
  { to: "/admin/products", label: "Products", icon: <FilePlus size={20} /> },
  { to: "/admin/categories", label: "Categories", icon: <Tag size={20} /> },
  { to: "/admin/orders", label: "Orders", icon: <ShoppingCart size={20} /> },
  { to: "/admin/reviews", label: "Reviews", icon: <Star size={20} /> },
  {
    to: "/admin/analytics/charts",
    label: "Analytics",
    icon: <BarChart2 size={20} />,
  },
];

export default function AdminSidebar() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);

  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [hoveredLink, setHoveredLink] = useState(null);

  // Auto collapse on small screens
  useEffect(() => {
    const handleResize = () => setCollapsed(window.innerWidth < 768);
    handleResize(); // initial check
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  return (
    <>
      {/* Mobile Hamburger */}
      <button
        className="md:hidden fixed top-4 left-4 z-50 p-2 bg-primary-700 text-white rounded-lg"
        onClick={() => setIsMobileOpen(true)}
      >
        <Menu size={24} />
      </button>

      {/* Overlay */}
      <AnimatePresence>
        {isMobileOpen && (
          <motion.div
            className="fixed inset-0 bg-black z-40"
            style={{ backgroundColor: "rgba(0,0,0,0.5)" }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setIsMobileOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <motion.aside
        animate={{ width: collapsed ? 64 : 256 }} // px width
        transition={{ type: "tween", duration: 0.2 }}
        className={`fixed md:static top-0 left-0 z-50 h-full bg-primary-700 text-white shadow-navbar flex flex-col`}
      >
        {/* Header */}
        <div
          className={`px-6 py-4 border-b border-primary-800 flex items-center justify-between ${
            collapsed ? "justify-center" : ""
          }`}
        >
          {!collapsed && <h1 className="text-xl font-bold">eStore Admin</h1>}
          <button
            className="md:hidden p-1"
            onClick={() => setIsMobileOpen(false)}
          >
            <X size={20} />
          </button>
          {/* Collapse toggle */}
          <button
            className="hidden md:block p-1 ml-auto"
            onClick={() => setCollapsed(!collapsed)}
          >
            {collapsed ? <Menu size={20} /> : <X size={20} />}
          </button>
        </div>

        {/* Links */}
        <nav className="px-2 py-6 space-y-2 overflow-y-auto flex flex-col items-stretch">
          {LINKS.map(({ to, label, icon }) => (
            <div
              key={to}
              className="relative group"
              onMouseEnter={() => setHoveredLink(to)}
              onMouseLeave={() => setHoveredLink(null)}
            >
              <NavLink
                to={to}
                onClick={() => setIsMobileOpen(false)}
                className={({ isActive }) =>
                  `flex items-center ${
                    collapsed ? "justify-center" : "px-4"
                  } py-2 rounded-lg transition ${
                    isActive ? "bg-primary-800" : "hover:bg-primary-600"
                  }`
                }
              >
                <span className="flex-shrink-0">{icon}</span>
                {!collapsed && <span className="ml-3">{label}</span>}
              </NavLink>

              {/* Smooth sliding tooltip for collapsed sidebar */}
              {collapsed && hoveredLink === to && (
                <AnimatePresence>
                  <motion.div
                    className="absolute left-full top-1/2 transform -translate-y-1/2 px-3 py-1 text-sm font-medium text-white bg-black rounded whitespace-nowrap shadow-lg z-50"
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ type: "spring", stiffness: 300, damping: 25 }}
                  >
                    {label}
                  </motion.div>
                </AnimatePresence>
              )}
            </div>
          ))}
        </nav>

        {/* Footer */}
        {!collapsed && (
          <div className="mt-auto px-6 py-4 border-t border-primary-800">
            <p className="text-sm">Signed in as</p>
            <p className="font-medium">{user?.name}</p>
            <Button
              variant="default"
              className="mt-3 w-full flex items-center justify-center"
              onClick={logout}
            >
              <LogOut size={18} className="mr-2" /> Logout
            </Button>
          </div>
        )}
      </motion.aside>
    </>
  );
}
