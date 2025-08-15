// src/store/useAuthStore.js
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

const API_BASE = import.meta.env.VITE_API_URL?.trim() || '';

const useAuthStore = create(
  persist(
    (set, get) => ({
      // ── State ───────────────────────────────────────────────────────────
      user: null,
      loading: false,
      error: null,

      hydrated: false,        // indicates storage rehydration
      sessionExpired: false,  // flag for idle/logout message
      skipIdleWarning: false, // flag for idle modal suppression

      // ── Actions ─────────────────────────────────────────────────────────
      
      // Set user in state
      setUser: (userData) => set({ user: userData }),

      // Fetch current user profile from backend
      fetchUser: async () => {
        set({ loading: true, error: null });
        try {
          const res = await fetch(`${API_BASE}/api/users/profile`, {
            credentials: 'include', // sends cookies
          });

          if (!res.ok) throw new Error('Not authenticated');

          const user = await res.json();
          set({ user, error: null });
        } catch (err) {
          console.error('Fetch user failed:', err);
          set({ user: null, error: err.message || 'Authentication error' });
        } finally {
          set({ loading: false });
        }
      },

      // Logout user and clear state
      logout: async () => {
        set({ user: null, sessionExpired: false });
        try {
          await fetch(`${API_BASE}/api/users/logout`, {
            method: 'POST',
            credentials: 'include',
          });
        } catch (err) {
          console.warn('Logout request failed:', err);
        }
      },

      // Session handling flags
      setSessionExpired: (val) => set({ sessionExpired: val }),
      setSkipIdleWarning: (val) => set({ skipIdleWarning: val }),
    }),
    {
      name: 'auth-storage', // Key in localStorage
      partialize: (state) => ({ user: state.user }), // Persist only user
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
