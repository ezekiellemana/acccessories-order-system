import React, { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import api from "../services/api";
import useAuthStore from "../store/useAuthStore";
import { motion } from "framer-motion";
import AnimatedButton from "../components/AnimatedButton";
import { toast } from "react-toastify";
import { Eye, EyeOff } from "lucide-react";
import {
  Card,
  CardHeader,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const setUser = useAuthStore((s) => s.setUser);
  const navigate = useNavigate();

  useEffect(() => {
    window.history.pushState(null, "", window.location.href);
    const blockNav = () =>
      window.history.pushState(null, "", window.location.href);
    window.addEventListener("popstate", blockNav);
    return () => window.removeEventListener("popstate", blockNav);
  }, []);

  const validate = () => {
    if (!/\S+@\S+\.\S+/.test(email)) {
      toast.error("Invalid email address");
      return false;
    }
    if (password.length < 6) {
      toast.error("Password must be at least 6 characters");
      return false;
    }
    return true;
  };

  const submit = async (e) => {
    e.preventDefault();
    if (!validate()) return;
    setLoading(true);
    try {
      const { data } = await api.post("/api/users/login", { email, password });
      const userData = data.user;
      setUser(userData);
      toast.success(
        userData.isAdmin
          ? `Welcome Admin, ${userData.name}!`
          : `Welcome back, ${userData.name}!`
      );
      navigate(userData.isAdmin ? "/admin" : "/profile", { replace: true });
    } catch (err) {
      console.error(err);
      setPassword("");
      toast.error(err.response?.data?.error || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-100 via-white to-accent-50 dark:from-neutral-900 dark:via-neutral-800 dark:to-neutral-900 px-4">
      <motion.div
        className="w-full max-w-md"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.4 }}
      >
        <Card className="p-8 bg-white dark:bg-neutral-800 rounded-2xl shadow-xl hover:shadow-2xl transition-shadow">
          <CardHeader className="text-center">
            <h2 className="text-3xl font-bold text-neutral-800 dark:text-neutral-100 mb-2">
              Welcome Back
            </h2>
            <p className="text-neutral-500 dark:text-neutral-400 text-sm">
              Please log in to your account
            </p>
          </CardHeader>

          <CardContent className="space-y-5">
            {/* Email Input */}
            <div>
              <Label htmlFor="email" className="text-sm font-medium">
                Email
              </Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                className="mt-2 focus:ring-2 focus:ring-accent-500 transition"
              />
            </div>

            {/* Password Input */}
            <div className="relative">
              <Label htmlFor="password" className="text-sm font-medium">
                Password
              </Label>
              <Input
                id="password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Your password"
                className="mt-2 pr-12 focus:ring-2 focus:ring-accent-500 transition"
              />
              <button
                type="button"
                onClick={() => setShowPassword((p) => !p)}
                className="absolute top-11 right-4 text-neutral-410 hover:text-neutral-600 dark:hover:text-accent-500 transition"
              >
                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>

            {/* Submit Button */}
            <AnimatedButton
              type="submit"
              className="w-full py-3 mt-4 bg-gradient-to-r from-accent-500 to-accent-700 text-white rounded-xl text-lg font-semibold shadow hover:shadow-lg transition-all"
              onClick={submit}
              disabled={loading}
            >
              {loading ? "Logging in…" : "Log In"}
            </AnimatedButton>
          </CardContent>

          <CardFooter className="text-center pt-6">
            <p className="text-neutral-600 dark:text-neutral-400 text-sm">
              Don’t have an account?{" "}
              <Link
                to="/signup"
                className="text-accent-500 hover:underline font-medium"
              >
                Sign Up
              </Link>
            </p>
          </CardFooter>
        </Card>
      </motion.div>
    </div>
  );
}
