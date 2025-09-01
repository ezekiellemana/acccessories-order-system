// src/pages/VerifyEmail.jsx
import React, { useState, useEffect } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import api from "../services/api";
import { toast } from "react-toastify";
import { motion } from "framer-motion";
import {
  Card,
  CardHeader,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export default function VerifyEmail() {
  const { token } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState("verifying");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [resendEmail, setResendEmail] = useState("");
  const [showEmailInput, setShowEmailInput] = useState(false);

  useEffect(() => {
    const verifyEmailToken = async () => {
      try {
        setLoading(true);
        const { data } = await api.get(`/api/users/verify-email/${token}`);

        setStatus("success");
        toast.success(data.message || "Email verified successfully!");

        // Update auth store here if needed
        if (data.user) {
          // e.g., setUser(data.user);
        }

        setTimeout(() => navigate("/profile"), 3000);
      } catch (err) {
        console.error("Verification error:", err);
        setStatus("error");
        setError(
          err.response?.data?.error ||
            "Failed to verify email. The link may be invalid or expired."
        );
        toast.error(err.response?.data?.error || "Verification failed");
      } finally {
        setLoading(false);
      }
    };

    if (token) verifyEmailToken();
  }, [token, navigate]);

  const handleResendVerification = async () => {
    try {
      let emailToSend = resendEmail;
      if (!emailToSend) {
        setShowEmailInput(true);
        toast.info("Please enter your email to resend verification.");
        return;
      }

      await api.post("/api/users/resend-verification", { email: emailToSend });
      toast.success("Verification email sent! Check your inbox.");
      setShowEmailInput(false);
    } catch (err) {
      toast.error(
        err.response?.data?.error || "Failed to resend verification email"
      );
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-100 via-white to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
        <Card className="text-center p-8">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600 mx-auto mb-4"></div>
          <h2 className="text-xl font-semibold">Verifying your email...</h2>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Please wait while we verify your email address.
          </p>
        </Card>
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
              Email Verification
            </h2>
          </CardHeader>

          <CardContent className="space-y-6 text-center">
            {status === "success" && (
              <div className="space-y-4">
                <div className="w-16 h-16 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center mx-auto">
                  <svg
                    className="w-8 h-8 text-green-600 dark:text-green-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M5 13l4 4L19 7"
                    />
                  </svg>
                </div>
                <h3 className="text-xl font-semibold text-green-600 dark:text-green-400">
                  Email Verified Successfully!
                </h3>
                <p className="text-gray-600 dark:text-gray-400">
                  Your email has been verified. Redirecting to your profile...
                </p>
                <div className="pt-4">
                  <Button
                    onClick={() => navigate("/profile")}
                    className="w-full"
                  >
                    Go to Profile Now
                  </Button>
                </div>
              </div>
            )}

            {status === "error" && (
              <div className="space-y-4">
                <div className="w-16 h-16 bg-red-100 dark:bg-red-900 rounded-full flex items-center justify-center mx-auto">
                  <svg
                    className="w-8 h-8 text-red-600 dark:text-red-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M6 18L18 6M6 6l12 12"
                    />
                  </svg>
                </div>
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400">
                  Verification Failed
                </h3>
                <p className="text-gray-600 dark:text-gray-400">{error}</p>

                {showEmailInput && (
                  <div className="mb-3">
                    <Input
                      type="email"
                      placeholder="Enter your email"
                      value={resendEmail}
                      onChange={(e) => setResendEmail(e.target.value)}
                    />
                  </div>
                )}

                <div className="space-y-3 pt-4">
                  <Button onClick={handleResendVerification} className="w-full">
                    Resend Verification Email
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => navigate("/signup")}
                    className="w-full"
                  >
                    Back to Sign Up
                  </Button>
                </div>
              </div>
            )}
          </CardContent>

          <CardFooter className="text-center pt-4">
            <p className="text-gray-600 dark:text-gray-400 text-sm">
              Need help?{" "}
              <Link
                to="/contact"
                className="text-purple-500 font-medium hover:underline"
              >
                Contact support
              </Link>
            </p>
          </CardFooter>
        </Card>
      </motion.div>
    </div>
  );
}
