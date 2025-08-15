// src/pages/OAuth.jsx

import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';

export default function OAuth() {
  const navigate = useNavigate();

  useEffect(() => {
    // 1) Read `?token=...` from URL
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');

    if (token) {
      // 2) Save JWT in localStorage or wherever you store it
      localStorage.setItem('token', token);
      toast.success('Logged in with Google!');
      // 3) Redirect the user into the app (e.g. home page)
      navigate('/', { replace: true });
    } else {
      // If no token was found in URL, show an error and go back to login
      toast.error('Google login failed. Please try again.');
      navigate('/login', { replace: true });
    }
  }, [navigate]);

  // Optional: you can show a quick “Logging in…” message
  return (
    <div className="h-screen flex items-center justify-center">
      <p className="text-neutral-500">Logging you in via Google…</p>
    </div>
  );
}
