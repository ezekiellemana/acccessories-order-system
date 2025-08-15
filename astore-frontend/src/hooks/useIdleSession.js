// src/hooks/useIdleSession.js
import { useEffect, useRef } from 'react';

export function useIdleSession({
  timeout = 10 * 60 * 1000,
  warningTime = 60 * 1000,
  onWarning = () => {},
  onLogout = () => {},
}) {
  const warnRef = useRef();
  const logoutRef = useRef();

  const resetTimers = () => {
    clearTimeout(warnRef.current);
    clearTimeout(logoutRef.current);
    warnRef.current = setTimeout(onWarning, timeout - warningTime);
    logoutRef.current = setTimeout(onLogout, timeout);
  };

  useEffect(() => {
    ['mousemove', 'mousedown', 'keydown', 'touchstart'].forEach((evt) =>
      window.addEventListener(evt, resetTimers)
    );
    resetTimers();
    return () => {
      clearTimeout(warnRef.current);
      clearTimeout(logoutRef.current);
      ['mousemove', 'mousedown', 'keydown', 'touchstart'].forEach((evt) =>
        window.removeEventListener(evt, resetTimers)
      );
    };
  }, [timeout, warningTime, onWarning, onLogout]);
}
