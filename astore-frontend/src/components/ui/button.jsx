import React from 'react';

const VARIANTS = {
  default: 'bg-primary-500 text-white hover:bg-primary-600',
  outline: 'border border-primary-500 text-primary-500 hover:bg-primary-50',
  ghost: 'bg-transparent hover:bg-primary-100',
};

export function Button({
  children,
  variant = 'default',
  className = '',
  ...props
}) {
  return (
    <button
      className={`px-4 py-2 rounded-2xl font-medium focus:outline-none transition ${VARIANTS[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
