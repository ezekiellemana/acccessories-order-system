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
import {
  getAuth,
  signInWithPopup,
  GoogleAuthProvider,
  sendPasswordResetEmail,
} from "firebase/auth";
import { app } from "../firebase/config";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [showResetModal, setShowResetModal] = useState(false);
  const [resetEmail, setResetEmail] = useState("");
  const [resetLoading, setResetLoading] = useState(false);

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

  const handlePasswordReset = async () => {
    if (!resetEmail || !/\S+@\S+\.\S+/.test(resetEmail)) {
      toast.error("Please enter a valid email address");
      return;
    }

    setResetLoading(true);
    try {
      console.log("Sending password reset to:", resetEmail);

      await sendPasswordResetEmail(auth, resetEmail);

      console.log("Password reset email sent successfully");
      toast.success(
        "Password reset email sent! Check your inbox and spam folder."
      );

      setShowResetModal(false);
      setResetEmail("");
    } catch (error) {
      console.error("Password reset error:", error);
      console.error("Error code:", error.code);
      console.error("Error message:", error.message);

      // More specific error handling
      switch (error.code) {
        case "auth/user-not-found":
          toast.error("No account found with this email address");
          break;
        case "auth/too-many-requests":
          toast.error("Too many attempts. Please try again later.");
          break;
        case "auth/invalid-email":
          toast.error("Invalid email address format");
          break;
        case "auth/operation-not-allowed":
          toast.error("Password reset is not enabled for this project");
          break;
        default:
          toast.error("Failed to send password reset email. Please try again.");
      }
    } finally {
      setResetLoading(false);
    }
  };

  return (
    <>
      {/* Password Reset Modal */}
      {showResetModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="bg-white dark:bg-gray-800 rounded-2xl p-6 w-full max-w-md"
          >
            <h3 className="text-xl font-bold mb-4 text-gray-800 dark:text-gray-100">
              Reset Your Password
            </h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Enter your email address and we'll send you a link to reset your
              password.
            </p>

            <Input
              type="email"
              value={resetEmail}
              onChange={(e) => setResetEmail(e.target.value)}
              placeholder="your@email.com"
              className="mb-4"
              disabled={resetLoading}
            />

            <div className="flex gap-3">
              <Button
                onClick={handlePasswordReset}
                disabled={resetLoading}
                className="flex-1"
              >
                {resetLoading ? "Sending..." : "Send Reset Link"}
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setShowResetModal(false);
                  setResetEmail("");
                }}
                disabled={resetLoading}
              >
                Cancel
              </Button>
            </div>
          </motion.div>
        </div>
      )}

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

              {/* Forgot Password Link */}
              <div className="text-right">
                <button
                  type="button"
                  onClick={() => setShowResetModal(true)}
                  className="text-sm text-purple-600 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300 transition-colors"
                >
                  Forgot your password?
                </button>
              </div>

              {/* Submit Button */}
              <AnimatedButton
                type="submit"
                className="w-full py-3 mt-2 bg-gradient-to-r from-purple-500 to-purple-700 text-white rounded-xl text-lg font-semibold shadow hover:shadow-lg transition-all"
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
    </>
  );
}

// Simple Button component if you don't have one
const Button = ({
  children,
  onClick,
  className = "",
  variant = "default",
  disabled = false,
  ...props
}) => {
  const baseClasses =
    "px-4 py-2 rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-purple-500";
  const variants = {
    default: "bg-purple-600 text-white hover:bg-purple-700 disabled:opacity-50",
    outline:
      "border border-gray-300 text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700",
  };

  return (
    <button
      className={`${baseClasses} ${variants[variant]} ${className}`}
      onClick={onClick}
      disabled={disabled}
      {...props}
    >
      {children}
    </button>
  );
};
