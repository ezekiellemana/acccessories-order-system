// src/components/Banner.jsx
import React from 'react';

export default function Banner({ message, onClose }) {
  return (
    <div className="w-full bg-yellow-200 text-yellow-900 px-4 py-2 flex justify-between items-center">
      <span>{message}</span>
      <button onClick={onClose} className="font-bold hover:underline" aria-label="Dismiss banner">
        ✕
      </button>
    </div>
  );
}
