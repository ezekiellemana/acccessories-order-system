// src/components/AdminLayout.jsx
import React from 'react';
import AdminSidebar from './AdminSidebar';

export default function AdminLayout({ children }) {
  return (
    <div className="min-h-screen flex bg-neutral-50 dark:bg-neutral-900">
      {/* Sidebar */}
      <aside className="hidden md:flex md:flex-shrink-0">
        <div className="flex flex-col w-64 lg:w-72 bg-white dark:bg-neutral-800 border-r border-neutral-200 dark:border-neutral-700">
          <AdminSidebar />
        </div>
      </aside>

      {/* Main content */}
      <div className="flex flex-col flex-1 overflow-hidden">
        <main className="flex-1 overflow-auto p-6 lg:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
