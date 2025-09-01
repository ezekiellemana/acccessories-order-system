// src/pages/Signup.jsx (updated)
import React, { useState, useRef, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import api from "../services/api";
import useAuthStore from "../store/useAuthStore";
import { toast } from "react-toastify";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import AnimatedButton from "../components/AnimatedButton";
import { Eye, EyeOff } from "lucide-react";
import { FcGoogle } from "react-icons/fc";
import {
  Card,
  CardHeader,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";

// Firebase imports
import {
  getAuth,
  signInWithPopup,
  GoogleAuthProvider,
  createUserWithEmailAndPassword,
  sendEmailVerification,
} from "firebase/auth";
import { app } from "../firebase/config";

// Add this utility function for fake domain detection
const isLikelyFakeEmail = (email) => {
  const fakeDomains = [
    "example.com",
    "test.com",
    "fake.com",
    "invalid.com",
    "nonexistent.com",
    "temp.com",
    "demo.com",
    "sample.com",
    "mailinator.com",
    "10minutemail.com",
    "guerrillamail.com",
    "throwawaymail.com",
    "disposable.com",
  ];

  const domain = email.split("@")[1]?.toLowerCase();
  return fakeDomains.includes(domain);
};

export default function Signup() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [verificationSent, setVerificationSent] = useState(false);
  const [emailValid, setEmailValid] = useState(true); // ADD THIS
  const [emailChecking, setEmailChecking] = useState(false); // ADD THIS

  const setUser = useAuthStore((s) => s.setUser);
  const setFirebaseUser = useAuthStore((s) => s.setFirebaseUser);
  const navigate = useNavigate();
  const nameRef = useRef(null);

  // Initialize Firebase auth
  const auth = getAuth(app);
  const googleProvider = new GoogleAuthProvider();

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

  // ADD THIS FUNCTION: Real-time email validation
  const checkEmailDomain = async (email) => {
    if (!email.includes("@")) {
      setEmailValid(true);
      return;
    }

    setEmailChecking(true);
    try {
      // Simple client-side check for common fake domains
      const isFake = isLikelyFakeEmail(email);

      if (isFake) {
        setEmailValid(false);
        setErrors({
          email:
            "This email domain appears to be invalid. Please use a real email address.",
        });
      } else {
        setEmailValid(true);
        // Clear email error if it was previously set
        if (errors.email) {
          setErrors({ ...errors, email: "" });
        }
      }
    } catch (error) {
      console.error("Email validation error:", error);
      setEmailValid(true); // Default to valid on error
    } finally {
      setEmailChecking(false);
    }
  };

  // ADD THIS FUNCTION: Handle email input changes
  const handleEmailChange = (e) => {
    const value = e.target.value;
    setEmail(value);

    // Clear previous email errors
    if (errors.email) {
      setErrors({ ...errors, email: "" });
    }

    // Validate email in real-time
    if (value.includes("@")) {
      checkEmailDomain(value);
    } else {
      setEmailValid(true);
    }
  };

  const submitHandler = async (e) => {
    e.preventDefault();

    if (!emailValid) {
      toast.error("Please use a valid email address");
      return;
    }

    const validationErrors = validate();
    if (Object.keys(validationErrors).length) {
      setErrors(validationErrors);
      return;
    }

    setLoading(true);
    setErrors({});

    try {
      // 1️⃣ Create Firebase user
      const auth = getAuth(app);
      const userCredential = await createUserWithEmailAndPassword(
        auth,
        email,
        password
      );
      const firebaseUser = userCredential.user;

      // 2️⃣ Send Firebase verification email
      await sendEmailVerification(firebaseUser);

      // 3️⃣ Send user to your backend (optional, for storing profile info)
      await api.post("/api/users/register", {
        name,
        email,
        password: "hidden", // Optional: never store raw password in backend
        firebaseUid: firebaseUser.uid,
      });

      // 4️⃣ Store email locally for resend verification
      localStorage.setItem("pendingVerificationEmail", email);

      // 5️⃣ Show verification screen
      setVerificationSent(true);
      toast.success(
        "Registration successful! Check your email to verify your account."
      );
    } catch (err) {
      console.error("Signup error:", err);

      if (err.code?.includes("auth/email-already-in-use")) {
        setErrors({ email: "This email is already registered." });
        toast.error("This email is already registered.");
      } else {
        setErrors({ submit: err.message || "Registration failed." });
        toast.error(err.message || "Registration failed.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignup = async () => {
    setGoogleLoading(true);
    setErrors({});

    try {
      const result = await signInWithPopup(auth, googleProvider);
      const firebaseUser = result.user;

      // Store Firebase user in state
      setFirebaseUser(firebaseUser);

      // Send user data to your backend
      const { data } = await api.post("/api/users/google-login", {
        uid: firebaseUser.uid,
        email: firebaseUser.email,
        name: firebaseUser.displayName || firebaseUser.email.split("@")[0],
        photoURL: firebaseUser.photoURL,
      });

      // Store backend user in state
      const userData = data.user;
      setUser(userData);

      toast.success("Account created with Google! You are now logged in.");
      navigate("/profile");
    } catch (error) {
      console.error("Google signup error:", error);

      // Handle specific Firebase errors
      if (error.code === "auth/popup-closed-by-user") {
        toast.error("Google sign-up was canceled");
      } else if (error.code === "auth/network-request-failed") {
        toast.error("Network error. Please check your connection");
      } else if (
        error.response?.data?.error ===
        "Email already exists with a different login method"
      ) {
        toast.error(
          "This email is already registered with a different login method"
        );
      } else {
        const errorMsg = error.response?.data?.error || "Google sign-up failed";
        setErrors({ submit: errorMsg });
        toast.error(errorMsg);
      }
    } finally {
      setGoogleLoading(false);
    }
  };

  const resendVerification = async () => {
    try {
      await api.post("/api/users/resend-verification", { email });
      toast.success("Verification email sent! Check your inbox.");
    } catch (error) {
      toast.error(
        error.response?.data?.error || "Failed to resend verification email"
      );
    }
  };

  if (verificationSent) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-100 via-white to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 px-4">
        <motion.div
          className="w-full sm:max-w-md"
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.4 }}
        >
          <Card className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-6">
            <CardHeader>
              <h2 className="text-3xl font-bold text-center text-gray-800 dark:text-gray-100 mb-4">
                Check Your Email
              </h2>
            </CardHeader>

            <CardContent className="space-y-6 text-center">
              <div className="w-16 h-16 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center mx-auto">
                <svg
                  className="w-8 h-8 text-blue-600 dark:text-blue-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                  />
                </svg>
              </div>

              <h3 className="text-xl font-semibold text-gray-800 dark:text-gray-200">
                Verify Your Email Address
              </h3>

              <p className="text-gray-600 dark:text-gray-400">
                We've sent a verification link to <strong>{email}</strong>.
                Please check your inbox and click the link to verify your email
                address.
              </p>

              <p className="text-sm text-gray-500 dark:text-gray-400">
                Didn't receive the email? Check your spam folder or click below
                to resend.
              </p>

              <div className="space-y-3 pt-4">
                <Button onClick={resendVerification} className="w-full">
                  Resend Verification Email
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setVerificationSent(false)}
                  className="w-full"
                >
                  Back to Sign Up
                </Button>
              </div>
            </CardContent>

            <CardFooter className="text-center pt-4">
              <p className="text-gray-600 dark:text-gray-400 text-sm">
                Already verified?{" "}
                <Link
                  to="/login"
                  className="text-purple-500 font-medium hover:underline"
                >
                  Log in here
                </Link>
              </p>
            </CardFooter>
          </Card>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-100 via-white to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 px-4">
      <motion.div
        className="w-full sm:max-w-md"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.4 }}
      >
        <Card className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-6">
          <CardHeader>
            <h2 className="text-3xl font-bold text-center text-gray-800 dark:text-gray-100 mb-4">
              Create an Account
            </h2>
          </CardHeader>

          <CardContent className="space-y-6">
            {errors.submit && (
              <p className="text-red-500 text-sm mb-4 text-center">
                {errors.submit}
              </p>
            )}

            {/* Google Sign Up Button */}
            <button
              onClick={handleGoogleSignup}
              disabled={loading || googleLoading}
              className="w-full flex items-center justify-center gap-3 py-3 px-4 border border-gray-300 dark:border-gray-600 rounded-xl text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors disabled:opacity-50"
            >
              <FcGoogle size={20} />
              <span className="text-sm font-medium">
                {googleLoading
                  ? "Signing up with Google..."
                  : "Sign up with Google"}
              </span>
            </button>

            {/* Divider */}
            <div className="relative flex items-center my-4">
              <div className="flex-grow border-t border-gray-300 dark:border-gray-600"></div>
              <span className="flex-shrink mx-4 text-gray-500 dark:text-gray-400 text-sm">
                Or continue with email
              </span>
              <div className="flex-grow border-t border-gray-300 dark:border-gray-600"></div>
            </div>

            <form onSubmit={submitHandler} className="space-y-4">
              {/* Name Field */}
              <div className="space-y-1">
                <Label
                  htmlFor="name"
                  className="text-gray-700 dark:text-gray-300"
                >
                  Full Name
                </Label>
                <Input
                  ref={nameRef}
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Your full name"
                  className="focus:ring-2 focus:ring-purple-500 dark:bg-gray-700 dark:text-white"
                  disabled={googleLoading}
                />
                {errors.name && (
                  <p className="text-red-500 text-sm">{errors.name}</p>
                )}
              </div>

              {/* Email Field */}
              <div className="space-y-1">
                <Label
                  htmlFor="email"
                  className="text-gray-700 dark:text-gray-300"
                >
                  Email Address
                </Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={handleEmailChange}
                  placeholder="you@example.com"
                  className={`focus:ring-2 focus:ring-purple-500 dark:bg-gray-700 dark:text-white ${
                    !emailValid ? "border-red-500 focus:ring-red-500" : ""
                  }`}
                  disabled={googleLoading}
                />
                {emailChecking && (
                  <p className="text-blue-500 text-sm">Checking email...</p>
                )}
                {errors.email && (
                  <p className="text-red-500 text-sm">{errors.email}</p>
                )}
                {!emailValid && !errors.email && (
                  <p className="text-red-500 text-sm">
                    This email domain doesn't appear to exist. Please use a
                    valid email.
                  </p>
                )}
              </div>

              {/* Password Field */}
              <div className="space-y-1">
                <Label
                  htmlFor="password"
                  className="text-gray-700 dark:text-gray-300"
                >
                  Password
                </Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Create a password"
                    className="pr-10 focus:ring-2 focus:ring-purple-500 dark:bg-gray-700 dark:text-white"
                    disabled={googleLoading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((p) => !p)}
                    className="absolute top-1/2 right-3 -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:hover:text-purple-500 focus:outline-none"
                    aria-label={
                      showPassword ? "Hide password" : "Show password"
                    }
                    disabled={googleLoading}
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
                <Label
                  htmlFor="confirm"
                  className="text-gray-700 dark:text-gray-300"
                >
                  Confirm Password
                </Label>
                <div className="relative">
                  <Input
                    id="confirm"
                    type={showConfirm ? "text" : "password"}
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    placeholder="Repeat your password"
                    className="pr-10 focus:ring-2 focus:ring-purple-500 dark:bg-gray-700 dark:text-white"
                    disabled={googleLoading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirm((p) => !p)}
                    className="absolute top-1/2 right-3 -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:hover:text-purple-500 focus:outline-none"
                    aria-label={
                      showConfirm
                        ? "Hide confirm password"
                        : "Show confirm password"
                    }
                    disabled={googleLoading}
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
                className="w-full mt-4 bg-gradient-to-r from-purple-500 to-purple-700 text-white rounded-xl text-lg font-semibold shadow hover:shadow-lg transition-all"
                disabled={loading || googleLoading || !emailValid}
              >
                {loading ? "Creating Account…" : "Sign Up with Email"}
              </AnimatedButton>
            </form>
          </CardContent>

          <CardFooter className="text-center pt-4">
            <p className="text-gray-600 dark:text-gray-400 text-sm">
              Already have an account?{" "}
              <Link
                to="/login"
                className="text-purple-500 font-medium hover:underline transition"
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
