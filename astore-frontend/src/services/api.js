import axios from "axios";
import { toast } from "react-toastify";
import useAuthStore from "../store/useAuthStore";

// ✅ Use VITE_API_URL or fallback to localhost
const baseURL = import.meta.env.VITE_API_URL?.trim() || "http://localhost:5000";
console.log("✅ API Base URL:", baseURL);

// ✅ Create Axios instance
const api = axios.create({
  baseURL,
  withCredentials: true, // For cookie-based auth if backend sets HttpOnly cookies
  headers: {
    "Content-Type": "application/json",
  },
});

// ✅ Request Interceptor: Add JWT token if available
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().token; // Get token from store
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ✅ Response Interceptor: Handle errors & refresh token
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
    const isRefreshCall = url.includes("/api/users/refresh");

    // ✅ Attempt silent refresh on 401 (once per request)
    if (
      status === 401 &&
      !config._retry &&
      !isAuthEndpoint &&
      !isAnalytics &&
      !isRefreshCall
    ) {
      config._retry = true;
      try {
        const refreshResponse = await api.post("/api/users/refresh");

        // ✅ Update token in store if refresh returns new token
        if (refreshResponse?.data?.token) {
          useAuthStore.getState().setToken(refreshResponse.data.token);
          config.headers.Authorization = `Bearer ${refreshResponse.data.token}`;
        }

        return api(config); // Retry original request
      } catch (refreshError) {
        useAuthStore.getState().logout();
        window.location.href = "/login";
        return Promise.reject(refreshError);
      }
    }

    // ✅ Global error handling
    if (error.message === "Network Error") {
      toast.error("🌐 Network error: Check your connection.");
    } else if (status === 401 && !isAuthEndpoint && !isAnalytics) {
      toast.error("🔒 Login required. Please sign in first.");
    } else if (status >= 500) {
      toast.error("💥 Server error. Try again later.");
    } else if (status === 400 && response?.data?.error) {
      toast.error(response.data.error);
    }

    return Promise.reject(error);
  }
);

export default api;
