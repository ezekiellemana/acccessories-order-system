import axios from "axios";
import { toast } from "react-toastify";
import { getAuth } from "firebase/auth"; // 🔹 Firebase Auth

// ✅ Use VITE_API_URL or fallback to localhost
const baseURL = import.meta.env.VITE_API_URL?.trim() || "http://localhost:5000";

// ✅ Create Axios instance
const api = axios.create({
  baseURL,
  withCredentials: true, // For cookie-based auth if backend sets HttpOnly cookies
  headers: {
    "Content-Type": "application/json",
  },
});

// ✅ Request Interceptor: Add Firebase ID token if available
api.interceptors.request.use(
  async (config) => {
    const user = getAuth().currentUser; // 🔹 Get logged-in Firebase user
    if (user) {
      const token = await user.getIdToken(); // 🔹 Get Firebase ID token
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ✅ Response Interceptor: Handle errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const { config = {}, response } = error;
    const status = response?.status;
    const url = config.url || "";

    const isAuthEndpoint =
      url.includes("/api/users/login") ||
      url.includes("/api/users/register") ||
      url.includes("/api/users/signup");
    const isAnalytics = url.includes("/api/admin/analytics");

    // 🔹 Firebase ID tokens are short-lived; for session-based refresh, backend handles it.
    if (status === 401 && !config._retry && !isAuthEndpoint && !isAnalytics) {
      toast.error("🔒 Login required. Please sign in first.");
      window.location.href = "/login";
      return Promise.reject(error);
    }

    // ✅ Global error handling
    if (error.message === "Network Error") {
      toast.error("🌐 Network error: Check your connection.");
    } else if (status >= 500) {
      toast.error("💥 Server error. Try again later.");
    } else if (status === 400 && response?.data?.error) {
      toast.error(response.data.error);
    }

    return Promise.reject(error);
  }
);

export default api;
