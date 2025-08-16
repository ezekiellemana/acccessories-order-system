// src/components/AdminLayout.jsx
import React, { useState } from "react";
import AdminSidebar from "./AdminSidebar";
import { X, Menu } from "lucide-react";

export default function AdminLayout({ children }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex min-h-screen bg-neutral-50 dark:bg-neutral-900">
      {/* Mobile Sidebar */}
      <div
        className={`fixed inset-0 z-40 md:hidden ${
          sidebarOpen ? "" : "pointer-events-none"
        }`}
      >
        <div
          className={`absolute inset-0 bg-black bg-opacity-50 transition-opacity ${
            sidebarOpen ? "opacity-100" : "opacity-0"
          }`}
          onClick={() => setSidebarOpen(false)}
        />
        <aside
          className={`fixed inset-y-0 left-0 w-64 bg-white dark:bg-neutral-800 shadow-lg transform transition-transform ${
            sidebarOpen ? "translate-x-0" : "-translate-x-full"
          }`}
        >
          <div className="flex justify-end p-4">
            <button onClick={() => setSidebarOpen(false)}>
              <X className="w-6 h-6 text-neutral-700 dark:text-neutral-200" />
            </button>
          </div>
          <AdminSidebar collapsed={collapsed} />
        </aside>
      </div>

      {/* Desktop Sidebar */}
      <aside
        className={`hidden md:flex flex-shrink-0 flex-col w-64 lg:w-72 bg-white dark:bg-neutral-800 border-r border-neutral-200 dark:border-neutral-700 transition-all duration-300 ${
          collapsed ? "w-20 lg:w-24" : ""
        }`}
      >
        <AdminSidebar collapsed={collapsed} />
        <button
          className="mt-auto p-2 text-sm text-neutral-600 dark:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-neutral-700"
          onClick={() => setCollapsed(!collapsed)}
        >
          {collapsed ? "➡️" : "⬅️"}
        </button>
      </aside>

      {/* Main content */}
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Header */}
        <header className="w-full h-16 bg-white dark:bg-neutral-800 shadow flex items-center justify-between px-4 lg:px-8">
          <div className="flex items-center gap-4">
            {/* Mobile menu button */}
            <button
              className="md:hidden p-2 text-neutral-700 dark:text-neutral-200"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu className="w-6 h-6" />
            </button>
            <h1 className="text-lg font-bold text-neutral-900 dark:text-neutral-100">
              Admin Dashboard
            </h1>
          </div>
          {/* Profile / actions placeholder */}
          <div>{/* Add notifications, profile menu, etc. */}</div>
        </header>

        {/* Main content area */}
        <main className="flex-1 overflow-auto p-6 lg:p-8 scrollbar-thin scrollbar-thumb-gray-300 dark:scrollbar-thumb-neutral-700">
          {children}
        </main>
      </div>
    </div>
  );
}
