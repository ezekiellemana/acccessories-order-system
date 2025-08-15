import React, { useState, useRef, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../services/api';
import useAuthStore from '../store/useAuthStore';
import { toast } from 'react-toastify';
import { motion } from 'framer-motion';
import AnimatedButton from '../components/AnimatedButton';
import { Eye, EyeOff } from 'lucide-react';
import { Card, CardHeader, CardContent, CardFooter } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';

export default function Signup() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});

  const setUser = useAuthStore((s) => s.setUser);
  const navigate = useNavigate();
  const nameRef = useRef(null);

  // Auto-focus name field on mount
  useEffect(() => {
    nameRef.current?.focus();
  }, []);

  // Client-side validation
  const validate = () => {
    const errs = {};
    if (!name.trim()) errs.name = 'Name is required.';
    if (!/\S+@\S+\.\S+/.test(email)) errs.email = 'Enter a valid email address.';
    if (password.length < 6) errs.password = 'Password must be at least 6 characters.';
    if (password !== confirm) errs.confirm = 'Passwords do not match.';
    return errs;
  };

  const submitHandler = async (e) => {
    e.preventDefault();
    const validationErrors = validate();
    if (Object.keys(validationErrors).length) {
      setErrors(validationErrors);
      return;
    }

    setLoading(true);
    setErrors({});

    try {
      // Register user and set session cookie
      await api.post('/api/users/register', { name, email, password });
      // Immediately login to establish session
      await api.post('/api/users/login', { email, password });
      // Fetch profile and update store
      const { data: userData } = await api.get('/api/users/profile');
      setUser(userData);

      toast.success('Account created! You are now logged in.');
      navigate('/profile');
    } catch (err) {
      console.error('Signup error:', err);
      const msg =
        err.response?.data?.error ||
        err.response?.data?.errors?.map((v) => v.msg).join(', ') ||
        'Registration failed. Please check your info.';
      setErrors({ submit: msg });
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-primary-50 px-4">
      <motion.div
        className="w-full max-w-md"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        whileHover={{ scale: 1.02 }}
        transition={{ duration: 0.4 }}
      >
        <Card className="relative bg-white rounded-2xl shadow-lg p-6">
          <CardHeader>
            <h2 className="text-3xl font-bold text-center text-neutral-800 mb-4">Sign Up</h2>
          </CardHeader>

          <CardContent>
            {errors.submit && (
              <p className="text-red-500 text-sm mb-4">{errors.submit}</p>
            )}

            <form onSubmit={submitHandler} className="space-y-6">
              {/* Name Field */}
              <div>
                <Label htmlFor="name">Name</Label>
                <Input
                  ref={nameRef}
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Your full name"
                />
                {errors.name && (
                  <span className="text-red-500 text-sm">{errors.name}</span>
                )}
              </div>

              {/* Email Field */}
              <div>
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                />
                {errors.email && (
                  <span className="text-red-500 text-sm">{errors.email}</span>
                )}
              </div>

              {/* Password Field */}
              <div className="relative">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Create a password"
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((p) => !p)}
                  className="absolute top-10 right-3 text-neutral-500 hover:text-neutral-700 focus:outline-none"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
                {errors.password && (
                  <span className="text-red-500 text-sm">{errors.password}</span>
                )}
              </div>

              {/* Confirm Password Field */}
              <div className="relative">
                <Label htmlFor="confirm">Confirm Password</Label>
                <Input
                  id="confirm"
                  type={showConfirm ? 'text' : 'password'}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="Repeat your password"
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirm((p) => !p)}
                  className="absolute top-10 right-3 text-neutral-500 hover:text-neutral-700 focus:outline-none"
                  aria-label={showConfirm ? 'Hide confirm password' : 'Show confirm password'}
                >
                  {showConfirm ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
                {errors.confirm && (
                  <span className="text-red-500 text-sm">{errors.confirm}</span>
                )}
              </div>

              <AnimatedButton type="submit" className="w-full" disabled={loading}>
                {loading ? 'Signing Up…' : 'Sign Up'}
              </AnimatedButton>
            </form>
          </CardContent>

          <CardFooter className="text-center pt-4">
            <p className="text-neutral-600 text-sm">
              Already have an account?{' '}
              <Link to="/login" className="text-accent-500 hover:underline">
                Log In
              </Link>
            </p>
          </CardFooter>
        </Card>
      </motion.div>
    </div>
  );
}
