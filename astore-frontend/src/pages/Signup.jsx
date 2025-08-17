import React, { useState, useRef, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import api from "../services/api";
import useAuthStore from "../store/useAuthStore";
import { toast } from "react-toastify";
import { motion } from "framer-motion";
import AnimatedButton from "../components/AnimatedButton";
import { Eye, EyeOff } from "lucide-react";
import {
  Card,
  CardHeader,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";

export default function Signup() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
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
    if (!name.trim()) errs.name = "Name is required.";
    if (!/\S+@\S+\.\S+/.test(email))
      errs.email = "Enter a valid email address.";
    if (password.length < 6)
      errs.password = "Password must be at least 6 characters.";
    if (password !== confirm) errs.confirm = "Passwords do not match.";
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
      await api.post("/api/users/register", { name, email, password });
      await api.post("/api/users/login", { email, password });
      const { data: userData } = await api.get("/api/users/profile");
      setUser(userData);

      toast.success("Account created! You are now logged in.");
      navigate("/profile");
    } catch (err) {
      console.error("Signup error:", err);
      const msg =
        err.response?.data?.error ||
        err.response?.data?.errors?.map((v) => v.msg).join(", ") ||
        "Registration failed. Please check your info.";
      setErrors({ submit: msg });
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-primary-50 px-4">
      <motion.div
        className="w-full sm:max-w-md"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.4 }}
      >
        <Card className="bg-white rounded-3xl shadow-xl p-6">
          <CardHeader>
            <h2 className="text-3xl font-bold text-center text-neutral-800 mb-4">
              Create an Account
            </h2>
          </CardHeader>

          <CardContent>
            {errors.submit && (
              <p className="text-red-500 text-sm mb-4">{errors.submit}</p>
            )}

            <form onSubmit={submitHandler} className="space-y-6">
              {/* Name Field */}
              <div className="space-y-1">
                <Label htmlFor="name">Full Name</Label>
                <Input
                  ref={nameRef}
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Your full name"
                  className="focus:ring-2 focus:ring-accent-500"
                />
                {errors.name && (
                  <p className="text-red-500 text-sm">{errors.name}</p>
                )}
              </div>

              {/* Email Field */}
              <div className="space-y-1">
                <Label htmlFor="email">Email Address</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  className="focus:ring-2 focus:ring-accent-500"
                />
                {errors.email && (
                  <p className="text-red-500 text-sm">{errors.email}</p>
                )}
              </div>

              {/* Password Field */}
              <div className="space-y-1">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Create a password"
                    className="pr-10 focus:ring-2 focus:ring-accent-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((p) => !p)}
                    className="absolute top-1/2 right-3 -translate-y-1/2 text-neutral-500 hover:text-neutral-700 focus:outline-none"
                    aria-label={
                      showPassword ? "Hide password" : "Show password"
                    }
                  >
                    {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                  </button>
                </div>
                {errors.password && (
                  <p className="text-red-500 text-sm">{errors.password}</p>
                )}
              </div>

              {/* Confirm Password Field */}
              <div className="space-y-1">
                <Label htmlFor="confirm">Confirm Password</Label>
                <div className="relative">
                  <Input
                    id="confirm"
                    type={showConfirm ? "text" : "password"}
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    placeholder="Repeat your password"
                    className="pr-10 focus:ring-2 focus:ring-accent-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirm((p) => !p)}
                    className="absolute top-1/2 right-3 -translate-y-1/2 text-neutral-500 hover:text-neutral-700 focus:outline-none"
                    aria-label={
                      showConfirm
                        ? "Hide confirm password"
                        : "Show confirm password"
                    }
                  >
                    {showConfirm ? <EyeOff size={20} /> : <Eye size={20} />}
                  </button>
                </div>
                {errors.confirm && (
                  <p className="text-red-500 text-sm">{errors.confirm}</p>
                )}
              </div>

              <AnimatedButton
                type="submit"
                className="w-full mt-4"
                disabled={loading}
              >
                {loading ? "Creating Account…" : "Sign Up"}
              </AnimatedButton>
            </form>
          </CardContent>

          <CardFooter className="text-center pt-4">
            <p className="text-neutral-600 text-sm">
              Already have an account?{" "}
              <Link
                to="/login"
                className="text-accent-500 font-medium hover:underline transition"
              >
                Log In
              </Link>
            </p>
          </CardFooter>
        </Card>
      </motion.div>
    </div>
  );
}
