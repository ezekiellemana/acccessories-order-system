// src/components/ui/dialog.jsx
import React from 'react';

/**
 * Stubbed Dialog components that respect the `open` prop.
 */

// Only render children when `open` is true
export function Dialog({ children, open, onOpenChange }) {
  if (!open) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 flex items-center justify-center z-50"
      onClick={() => {
        /* clicking backdrop could call onOpenChange(false) if you like */
        // if (onOpenChange) onOpenChange(false);
      }}
    >
      {children}
    </div>
  );
}

export function DialogContent({ children, className = '', ...props }) {
  // stop clicks inside content from closing
  return (
    <div
      className={`bg-white dark:bg-gray-800 rounded-2xl shadow-md p-6 ${className}`}
      onClick={(e) => e.stopPropagation()}
      {...props}
    >
      {children}
    </div>
  );
}

export function DialogHeader({ children, className = '', ...props }) {
  return (
    <div className={`mb-4 ${className}`} {...props}>
      {children}
    </div>
  );
}

export function DialogTitle({ children, className = '', ...props }) {
  return (
    <h2 className={`text-xl font-semibold mb-2 ${className}`} {...props}>
      {children}
    </h2>
  );
}

export function DialogDescription({ children, className = '', ...props }) {
  return (
    <p className={`text-sm mb-4 ${className}`} {...props}>
      {children}
    </p>
  );
}

export function DialogFooter({ children, className = '', ...props }) {
  return (
    <div className={`flex justify-end space-x-2 mt-4 ${className}`} {...props}>
      {children}
    </div>
  );
}
