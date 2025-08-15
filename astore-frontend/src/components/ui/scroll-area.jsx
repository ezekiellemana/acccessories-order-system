import React from 'react';

/**
 * Stubbed ScrollArea so imports resolve.
 * Swap out with a proper scroll container implementation later.
 */
export function ScrollArea({ children, className = '' }) {
  return (
    <div className={`overflow-auto ${className}`}>
      {children}
    </div>
  );
}
