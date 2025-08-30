// src/store/useAuthStore.js
import { create } from "zustand";
import { persist } from "zustand/middleware";
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut,
} from "firebase/auth";
import { app } from "../firebase/config";

const API_BASE =
  import.meta.env.VITE_API_URL?.trim() || "http://localhost:5000";

// Initialize Firebase auth
const auth = getAuth(app);

const useAuthStore = create(
  persist(
    (set, get) => ({
      // ── State ──────────────────────────────
      user: null,
      firebaseUser: null, // Firebase user object
      loading: false,
      error: null,
      hydrated: false,
      sessionExpired: false,
      skipIdleWarning: false,

      // ── Actions ────────────────────────────

      setUser: (userData) => set({ user: userData }),
      setFirebaseUser: (firebaseUser) => set({ firebaseUser }),

      // Fetch user profile from backend using Firebase token
      fetchUser: async () => {
        set({ loading: true, error: null });
        try {
          const firebaseUser = auth.currentUser;
          if (!firebaseUser) throw new Error("Not authenticated");

          const idToken = await firebaseUser.getIdToken();

          const res = await fetch(`${API_BASE}/api/users/profile`, {
            headers: {
              Authorization: `Bearer ${idToken}`,
            },
          });

          if (!res.ok) throw new Error("Failed to fetch user profile");

          const user = await res.json();
          set({ user, error: null });
        } catch (err) {
          console.error("Fetch user failed:", err);
          set({ user: null, error: err.message || "Authentication error" });
        } finally {
          set({ loading: false });
        }
      },

      // Google login
      loginWithGoogle: async () => {
        set({ loading: true, error: null });
        try {
          const provider = new GoogleAuthProvider();
          const result = await signInWithPopup(auth, provider);

          // Save Firebase user
          set({ firebaseUser: result.user });

          // Fetch backend profile
          await get().fetchUser();

          return { success: true };
        } catch (err) {
          console.error("Google login failed:", err);
          set({ error: err.message || "Google authentication failed" });
          return { success: false, error: err.message };
        } finally {
          set({ loading: false });
        }
      },

      // Logout both Firebase and backend
      logout: async () => {
        const { firebaseUser } = get();

        // Sign out from Firebase if exists
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

        // Backend logout
        try {
          await fetch(`${API_BASE}/api/users/logout`, {
            method: "POST",
            credentials: "include",
          });
        } catch (err) {
          console.warn("Backend logout request failed:", err);
        }
      },

      // Clear Firebase auth only
      clearFirebaseAuth: () => {
        set({ firebaseUser: null });
        try {
          signOut(auth);
        } catch (err) {
          console.warn("Firebase signout failed:", err);
        }
      },

      setSessionExpired: (val) => set({ sessionExpired: val }),
      setSkipIdleWarning: (val) => set({ skipIdleWarning: val }),
    }),
    {
      name: "auth-storage",
      partialize: (state) => ({
        user: state.user,
        // Don't persist firebaseUser
      }),
      onRehydrateStorage: () => (state) => {
        setTimeout(() => {
          state.hydrated = true;
        }, 0);
      },
    }
  )
);

export default useAuthStore;
