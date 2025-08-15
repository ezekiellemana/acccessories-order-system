// src/components/ProtectedRoute.jsx
import React, { useEffect, useState } from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import api from '../services/api';
import { useAuthStore } from '../store/useAuthStore';

export default function ProtectedRoute() {
  const [loading, setLoading] = useState(true);
  const user = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);

  useEffect(() => {
    if (user) {
      setLoading(false);
    } else {
      api
        .get('/api/users/profile')
        .then(({ data }) => setUser(data))
        .catch(() => {})
        .finally(() => setLoading(false));
    }
  }, [user, setUser]);

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center text-lg text-neutral-500">
        Loading…
      </div>
    );
  }

  return user ? <Outlet /> : <Navigate to="/login" replace />;
}
