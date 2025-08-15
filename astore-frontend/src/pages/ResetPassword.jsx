// src/pages/ResetPassword.jsx
import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../services/api';
import { toast } from 'react-toastify';

export default function ResetPassword() {
  const { token } = useParams();
  const navigate = useNavigate();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      toast.error("Passwords don't match.");
      return;
    }
    setLoading(true);
    try {
      // Call backend reset endpoint
      const { data } = await api.post(`/api/users/reset-password/${token}`, {
        password,
        confirmPassword,
      });
      toast.success('Password reset successful!');
      // Save returned JWT (if any) and redirect to profile
      if (data.token) {
        localStorage.setItem('authToken', data.token);
        // Optionally fetch user profile and store in context…
      }
      navigate('/login');
    } catch (err) {
      console.error(err);
      toast.error(
        err.response?.data?.error || 'Reset link is invalid or expired.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto py-16">
      <h2 className="text-2xl font-semibold text-center mb-6">
        Reset Your Password
      </h2>
      <form onSubmit={handleSubmit} className="space-y-4 bg-white p-8 rounded-2xl shadow-card">
        <div>
          <label className="block text-sm font-medium text-neutral-700">New Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="mt-1 block w-full px-3 py-2 border border-neutral-300 rounded-2xl focus:outline-none focus:ring-2 focus:ring-primary-300"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-neutral-700">
            Confirm Password
          </label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            className="mt-1 block w-full px-3 py-2 border border-neutral-300 rounded-2xl focus:outline-none focus:ring-2 focus:ring-primary-300"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full py-2 bg-accent-600 text-white rounded-2xl hover:bg-accent-700 transition"
        >
          {loading ? 'Resetting…' : 'Reset Password'}
        </button>
      </form>
    </div>
  );
}
