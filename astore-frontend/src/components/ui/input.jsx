import React from 'react';

export function Input({ className = '', ...props }) {
  return (
    <input
      className={`w-full px-3 py-2 border border-neutral-300 rounded-2xl bg-neutral-50 focus:outline-none focus:ring-2 focus:ring-primary-300 transition ${className}`}
      {...props}
    />
  );
}
