// src/components/ui/switch.jsx
import React from 'react';

export function Switch({ checked, onCheckedChange }) {
  return (
    <button
      onClick={() => onCheckedChange(!checked)}
      aria-pressed={checked}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${
        checked ? 'bg-primary-500' : 'bg-neutral-300'
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
          checked ? 'translate-x-6' : 'translate-x-1'
        }`}
      />
    </button>
  );
}
