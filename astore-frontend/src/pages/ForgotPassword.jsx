// src/pages/ForgotPassword.jsx

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import { motion } from 'framer-motion';
import AnimatedButton from '../components/AnimatedButton';
import { toast } from 'react-toastify';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const submitHandler = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await api.post('/api/users/forgot-password', { email });
      toast.success(
        'If that email exists in our system, a reset link has been sent. Please check your inbox.'
      );
      // Optionally, navigate back to login or to a “Check your mailbox” page
      navigate('/login');
    } catch (err) {
      console.error(err);
      toast.error(
        err.response?.data?.error ||
          'Something went wrong. Please try again later.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-primary-50 px-4">
      <motion.div
        className="relative w-full max-w-md"
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.4 }}
      >
        <div className="absolute inset-0 bg-gradient-to-r from-primary-300 to-primary-500 rounded-3xl blur-xl opacity-30 pointer-events-none"></div>
        <motion.div
          className="relative bg-white rounded-2xl shadow-lg p-8"
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          <h2 className="text-3xl font-bold text-center text-neutral-800 mb-6">
            Forgot Password
          </h2>
          <form onSubmit={submitHandler} className="space-y-6">
            {/* Email Field */}
            <div className="relative">
              <input
                id="fp-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                placeholder=" "
                className="peer w-full px-3 py-2 border border-neutral-300 rounded-2xl bg-neutral-50 shadow-inner focus:outline-none focus:ring-2 focus:ring-primary-300 transition"
              />
              <label
                htmlFor="fp-email"
                className="absolute left-3 top-2 text-sm text-neutral-500 transition-all 
                           peer-placeholder-shown:top-2 peer-placeholder-shown:text-base peer-placeholder-shown:text-neutral-400
                           peer-focus:-top-3 peer-focus:text-sm peer-focus:text-primary-600"
              >
                Enter your email
              </label>
            </div>

            <motion.div whileHover={{ scale: 1.02 }} transition={{ duration: 0.2 }}>
              <AnimatedButton
                type="submit"
                className="w-full text-center"
                disabled={loading}
              >
                {loading ? 'Sending…' : 'Send Reset Link'}
              </AnimatedButton>
            </motion.div>

            <p className="mt-4 text-center text-neutral-600 text-sm">
              <button
                type="button"
                onClick={() => navigate('/login')}
                className="text-accent-500 hover:underline"
              >
                ← Back to Log In
              </button>
            </p>
          </form>
        </motion.div>
      </motion.div>
    </div>
  );
}
