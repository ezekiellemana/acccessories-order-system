// src/components/RedirectIfAdmin.jsx
import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import useAuthStore from '../store/useAuthStore';

export default function RedirectIfAdmin({ children, to = '/admin' }) {
  const user = useAuthStore((s) => s.user);
  const hydrated = useAuthStore((s) => s.hydrated);
  const navigate = useNavigate();

  useEffect(() => {
    if (hydrated && user?.isAdmin) {
      navigate(to, { replace: true });
    }
  }, [hydrated, user, navigate, to]);

  return <>{children}</>;
}
