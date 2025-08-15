// src/hooks/useIdleLogout.js
import { useEffect, useRef } from 'react';
import { getAuthStore } from '../store/useAuthStore';

export function useIdleLogout(timeoutMs = 15 * 60 * 1000) {
  const timer = useRef(null);

  const resetTimer = () => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      getAuthStore().logout();
    }, timeoutMs);
  };

  useEffect(() => {
    const events = ['mousemove', 'keydown', 'mousedown', 'touchstart'];
    events.forEach((evt) => window.addEventListener(evt, resetTimer));
    resetTimer(); // start the clock

    return () => {
      clearTimeout(timer.current);
      events.forEach((evt) => window.removeEventListener(evt, resetTimer));
    };
  }, [timeoutMs]);
}
