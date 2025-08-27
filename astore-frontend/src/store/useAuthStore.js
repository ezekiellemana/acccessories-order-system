// src/store/useAuthStore.js
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { getAuth, signOut } from "firebase/auth";
import { app } from "../firebase/config";

const API_BASE = import.meta.env.VITE_API_URL?.trim() || "";

// Initialize Firebase auth
const auth = getAuth(app);

const useAuthStore = create(
  persist(
    (set, get) => ({
      // ── State ───────────────────────────────────────────────────────────
      user: null,
      loading: false,
      error: null,
      firebaseUser: null, // Firebase user object

      hydrated: false, // indicates storage rehydration
      sessionExpired: false, // flag for idle/logout message
      skipIdleWarning: false, // flag for idle modal suppression

      // ── Actions ─────────────────────────────────────────────────────────

      // Set user in state
      setUser: (userData) => set({ user: userData }),

      // Set Firebase user
      setFirebaseUser: (firebaseUser) => set({ firebaseUser }),

      // Fetch current user profile from backend
      fetchUser: async () => {
        set({ loading: true, error: null });
        try {
          const res = await fetch(`${API_BASE}/api/users/profile`, {
            credentials: "include", // sends cookies
          });

          if (!res.ok) throw new Error("Not authenticated");

          const user = await res.json();
          set({ user, error: null });
        } catch (err) {
          console.error("Fetch user failed:", err);
          set({ user: null, error: err.message || "Authentication error" });
        } finally {
          set({ loading: false });
        }
      },

      // Login with Firebase Google auth
      loginWithGoogle: async () => {
        set({ loading: true, error: null });
        try {
          // This will be handled by the Firebase UI in the component
          // The actual authentication happens via popup in the component
          // This function is just a placeholder for consistency
          return { success: true };
        // eslint-disable-next-line no-unreachable
        } catch (err) {
          console.error("Google login failed:", err);
          set({ error: err.message || "Google authentication failed" });
          return { success: false, error: err.message };
        } finally {
          set({ loading: false });
        }
      },

      // Logout user and clear state (both backend and Firebase)
      logout: async () => {
        const { firebaseUser } = get();

        // Sign out from Firebase if there's a Firebase user
        if (firebaseUser) {
          try {
            await signOut(auth);
          } catch (err) {
            console.warn("Firebase logout failed:", err);
          }
        }

        // Clear state
        set({
          user: null,
          firebaseUser: null,
          sessionExpired: false,
        });

        // Call backend logout
        try {
          await fetch(`${API_BASE}/api/users/logout`, {
            method: "POST",
            credentials: "include",
          });
        } catch (err) {
          console.warn("Backend logout request failed:", err);
        }
      },

      // Clear only Firebase auth (keep backend session)
      clearFirebaseAuth: () => {
        set({ firebaseUser: null });
        try {
          signOut(auth);
        } catch (err) {
          console.warn("Firebase signout failed:", err);
        }
      },

      // Session handling flags
      setSessionExpired: (val) => set({ sessionExpired: val }),
      setSkipIdleWarning: (val) => set({ skipIdleWarning: val }),
    }),
    {
      name: "auth-storage", // Key in localStorage
      partialize: (state) => ({
        user: state.user,
        // Don't persist firebaseUser as it contains volatile data
      }),
      onRehydrateStorage: () => (state) => {
        // Mark as hydrated after persistence
        setTimeout(() => {
          state.hydrated = true;
        }, 0);
      },
    }
  )
);

export default useAuthStore;
