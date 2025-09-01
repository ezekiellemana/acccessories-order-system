// src/pages/Signup.jsx
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

// Fake domain detection
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
  const [emailValid, setEmailValid] = useState(true);
  const [emailChecking, setEmailChecking] = useState(false);

  const setUser = useAuthStore((s) => s.setUser);
  const setFirebaseUser = useAuthStore((s) => s.setFirebaseUser);
  const navigate = useNavigate();
  const nameRef = useRef(null);

  const auth = getAuth(app);
  const googleProvider = new GoogleAuthProvider();

  useEffect(() => {
    nameRef.current?.focus();
  }, []);

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

  const checkEmailDomain = (email) => {
    if (!email.includes("@")) {
      setEmailValid(true);
      return;
    }
    setEmailChecking(true);
    const isFake = isLikelyFakeEmail(email);
    if (isFake) {
      setEmailValid(false);
      setErrors({
        email:
          "This email domain appears to be invalid. Please use a real email address.",
      });
    } else {
      setEmailValid(true);
      if (errors.email) setErrors({ ...errors, email: "" });
    }
    setEmailChecking(false);
  };

  const handleEmailChange = (e) => {
    const value = e.target.value;
    setEmail(value);
    if (errors.email) setErrors({ ...errors, email: "" });
    if (value.includes("@")) checkEmailDomain(value);
    else setEmailValid(true);
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
      const userCredential = await createUserWithEmailAndPassword(
        auth,
        email,
        password
      );
      const firebaseUser = userCredential.user;

      await sendEmailVerification(firebaseUser);

      await api.post("/api/users/register", {
        name,
        email,
        password: "hidden",
        firebaseUid: firebaseUser.uid,
      });

      // Navigate to VerifyEmail page passing email
      navigate(`/verify-email/${firebaseUser.uid}`, { state: { email } });
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
      setFirebaseUser(firebaseUser);

      // Send user data to backend
      const { data } = await api.post("/api/users/google-login", {
        uid: firebaseUser.uid,
        email: firebaseUser.email,
        name: firebaseUser.displayName || firebaseUser.email.split("@")[0],
        photoURL: firebaseUser.photoURL,
      });

      // Store backend user in state
      const userData = data.user;
      setUser(userData);

      if (!userData.verified) {
        // If backend says user email is not verified, redirect to verify page
        navigate(`/verify-email/${firebaseUser.uid}`, {
          state: { email: firebaseUser.email },
        });
        toast.info("Please verify your email to complete signup.");
      } else {
        // Email is already verified, login directly
        toast.success("Logged in with Google!");
        navigate("/profile");
      }
    } catch (error) {
      console.error("Google signup error:", error);

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

  if (verificationSent) return null; // We'll always navigate to verify page now

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

            <div className="relative flex items-center my-4">
              <div className="flex-grow border-t border-gray-300 dark:border-gray-600"></div>
              <span className="flex-shrink mx-4 text-gray-500 dark:text-gray-400 text-sm">
                Or continue with email
              </span>
              <div className="flex-grow border-t border-gray-300 dark:border-gray-600"></div>
            </div>

            <form onSubmit={submitHandler} className="space-y-4">
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
              </div>

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
