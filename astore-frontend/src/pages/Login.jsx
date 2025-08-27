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
import { FcGoogle } from "react-icons/fc";

// Firebase imports
import { getAuth, signInWithPopup, GoogleAuthProvider } from "firebase/auth";
import { app } from "../firebase/config"; // Your Firebase configuration

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  // Get actions from auth store
  const { setUser, setFirebaseUser } = useAuthStore();
  const navigate = useNavigate();

  // Initialize Firebase auth
  const auth = getAuth(app);
  const googleProvider = new GoogleAuthProvider();

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

  const handleGoogleLogin = async () => {
    setGoogleLoading(true);
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const firebaseUser = result.user;

      // Store Firebase user in state
      setFirebaseUser(firebaseUser);

      // Send user data to your backend
      const { data } = await api.post("/api/users/google-login", {
        uid: firebaseUser.uid,
        email: firebaseUser.email,
        name: firebaseUser.displayName,
        photoURL: firebaseUser.photoURL,
      });

      // Store backend user in state
      const userData = data.user;
      setUser(userData);

      toast.success(
        userData.isAdmin
          ? `Welcome Admin, ${userData.name}!`
          : `Welcome back, ${userData.name}!`
      );
      navigate(userData.isAdmin ? "/admin" : "/profile", { replace: true });
    } catch (error) {
      console.error("Google login error:", error);

      // Handle specific Firebase errors
      if (error.code === "auth/popup-closed-by-user") {
        toast.error("Google sign-in was canceled");
      } else if (error.code === "auth/network-request-failed") {
        toast.error("Network error. Please check your connection");
      } else {
        toast.error(error.response?.data?.error || "Google login failed");
      }
    } finally {
      setGoogleLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-100 via-white to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 px-4">
      <motion.div
        className="w-full max-w-md"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.4 }}
      >
        <Card className="p-8 bg-white dark:bg-gray-800 rounded-2xl shadow-xl hover:shadow-2xl transition-shadow">
          <CardHeader className="text-center">
            <h2 className="text-3xl font-bold text-gray-800 dark:text-gray-100 mb-2">
              Welcome Back
            </h2>
            <p className="text-gray-500 dark:text-gray-400 text-sm">
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
                className="mt-2 focus:ring-2 focus:ring-purple-500 transition"
                disabled={googleLoading}
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
                className="mt-2 pr-12 focus:ring-2 focus:ring-purple-500 transition"
                disabled={googleLoading}
              />
              <button
                type="button"
                onClick={() => setShowPassword((p) => !p)}
                className="absolute top-11 right-4 text-gray-400 hover:text-gray-600 dark:hover:text-purple-500 transition"
                disabled={googleLoading}
              >
                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>

            {/* Submit Button */}
            <AnimatedButton
              type="submit"
              className="w-full py-3 mt-4 bg-gradient-to-r from-purple-500 to-purple-700 text-white rounded-xl text-lg font-semibold shadow hover:shadow-lg transition-all"
              onClick={submit}
              disabled={loading || googleLoading}
            >
              {loading ? "Logging in…" : "Log In"}
            </AnimatedButton>

            {/* Divider */}
            <div className="relative flex items-center my-6">
              <div className="flex-grow border-t border-gray-300 dark:border-gray-600"></div>
              <span className="flex-shrink mx-4 text-gray-500 dark:text-gray-400 text-sm">
                Or continue with
              </span>
              <div className="flex-grow border-t border-gray-300 dark:border-gray-600"></div>
            </div>

            {/* Google Login Button */}
            <button
              onClick={handleGoogleLogin}
              disabled={loading || googleLoading}
              className="w-full flex items-center justify-center gap-3 py-3 px-4 border border-gray-300 dark:border-gray-600 rounded-xl text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors disabled:opacity-50"
            >
              <FcGoogle size={20} />
              <span className="text-sm font-medium">
                {googleLoading
                  ? "Signing in with Google..."
                  : "Sign in with Google"}
              </span>
            </button>
          </CardContent>

          <CardFooter className="text-center pt-6">
            <p className="text-gray-600 dark:text-gray-400 text-sm">
              Don't have an account?{" "}
              <Link
                to="/signup"
                className="text-purple-500 hover:underline font-medium"
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
