import React from 'react';

export default function AnimatedButton({ children, ...props }) {
  return (
    <button
      {...props}
      className={`
        bg-gradient-to-r from-accent-400 to-accent-600
        text-white font-semibold rounded-2xl px-6 py-2 
        shadow-card hover:shadow-hoverCard 
        focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-accent-300
        disabled:opacity-50 disabled:cursor-not-allowed 
        transition-all duration-200 
        ${props.className || ''}
      `}
    >
      {children}
    </button>
  );
}
