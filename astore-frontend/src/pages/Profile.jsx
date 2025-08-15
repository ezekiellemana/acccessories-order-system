import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import useAuthStore from '../store/useAuthStore';
import api from '../services/api';
import { toast } from 'react-toastify';
import { motion } from 'framer-motion';

// Confirmation modal for deleting orders
function ConfirmModal({ visible, message, onConfirm, onCancel }) {
  if (!visible) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className="bg-white rounded-2xl shadow-lg p-6 max-w-sm w-full"
      >
        <p className="text-neutral-800 mb-4">{message}</p>
        <div className="flex justify-end space-x-4">
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-neutral-200 text-neutral-700 rounded-2xl hover:bg-neutral-300 transition"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 bg-red-600 text-white rounded-2xl hover:bg-red-700 transition"
          >
            Confirm
          </button>
        </div>
      </motion.div>
    </div>
  );
}

// Helper to fetch profile & update Zustand
async function fetchUserProfile() {
  try {
    const { data } = await api.get('/api/users/profile', { withCredentials: true });
    useAuthStore.getState().setUser(data);
    return data;
  } catch (e) {
    useAuthStore.getState().setUser(null);
    throw e;
  }
}

export default function Profile() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);

  // Hooks at top
  const [userInfo, setUserInfo] = useState({
    name: '',
    email: '',
    address: { street: '', city: '', country: '', postalCode: '' },
  });
  const [loadingUser, setLoadingUser] = useState(true);
  const [savingProfile, setSavingProfile] = useState(false);

  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [changingPassword, setChangingPassword] = useState(false);

  const [orders, setOrders] = useState([]);
  const [loadingOrders, setLoadingOrders] = useState(true);
  const [orderToDelete, setOrderToDelete] = useState(null);
  const [deletingId, setDeletingId] = useState(null);

  // Fetch orders
  const fetchOrders = async () => {
    setLoadingOrders(true);
    try {
      const { data } = await api.get('/api/orders/my');
      setOrders(data);
    } catch (err) {
      console.error('Failed to load orders:', err);
      toast.error('Could not load your orders.');
    } finally {
      setLoadingOrders(false);
    }
  };

  // Load profile & orders on mount
  useEffect(() => {
    (async () => {
      setLoadingUser(true);
      try {
        let currUser = user;
        if (!currUser) {
          currUser = await fetchUserProfile();
        }
        if (!currUser) throw new Error('No session/user found');

        setUserInfo({
          name: currUser.name || '',
          email: currUser.email || '',
          address: {
            street: currUser.address?.street || '',
            city: currUser.address?.city || '',
            country: currUser.address?.country || '',
            postalCode: currUser.address?.postalCode || '',
          },
        });
        await fetchOrders();
      } catch {
        toast.error('Session expired. Please log in.');
        navigate('/login', { replace: true });
      } finally {
        setLoadingUser(false);
      }
    })();
  }, [user, navigate]);

  // Handle form changes
  const handleProfileChange = (e) => {
    const { name, value } = e.target;
    if (name.includes('address.')) {
      const key = name.split('.')[1];
      setUserInfo((prev) => ({ ...prev, address: { ...prev.address, [key]: value } }));
    } else {
      setUserInfo((prev) => ({ ...prev, [name]: value }));
    }
  };

  // Submit profile updates
  const handleProfileSubmit = async (e) => {
    e.preventDefault();
    setSavingProfile(true);
    try {
      await api.put('/api/users/profile', {
        name: userInfo.name,
        email: userInfo.email,
        address: userInfo.address,
      });
      toast.success('Profile updated successfully.');
      const updatedUser = await fetchUserProfile();
      setUser(updatedUser);
    } catch (err) {
      console.error('Failed to update profile:', err);
      const msg = err.response?.data?.error || 'Could not update profile.';
      toast.error(msg);
    } finally {
      setSavingProfile(false);
    }
  };

  // Handle password form
  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setPasswordForm((prev) => ({ ...prev, [name]: value }));
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      return toast.error('Passwords do not match.');
    }
    setChangingPassword(true);
    try {
      await api.put('/api/users/password', {
        currentPassword: passwordForm.currentPassword,
        newPassword: passwordForm.newPassword,
      });
      toast.success('Password changed successfully.');
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
    } catch (err) {
      console.error('Failed to change password:', err);
      const msg = err.response?.data?.error || 'Could not change password.';
      toast.error(msg);
    } finally {
      setChangingPassword(false);
    }
  };

  // Order deletion handlers
  const confirmDeleteOrder = (orderId) => setOrderToDelete(orderId);
  const handleConfirmDelete = async () => {
    setDeletingId(orderToDelete);
    setOrderToDelete(null);
    try {
      await api.delete(`/api/orders/${deletingId}`);
      toast.success('Order removed.');
      setOrders((prev) => prev.filter((o) => o._id !== deletingId));
    } catch (err) {
      console.error('Failed to delete order:', err);
      toast.error('Could not delete order.');
    } finally {
      setDeletingId(null);
    }
  };
  const handleCancelDelete = () => setOrderToDelete(null);

  // Render loading state
  if (loadingUser) {
    return (
      <div className="flex justify-center items-center h-64">
        <p className="text-neutral-500">Loading profile…</p>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto p-6 space-y-10">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Profile Form */}
        <div className="bg-white rounded-2xl shadow-card p-6">
          <h2 className="text-2xl font-bold mb-4">My Profile</h2>
          <form onSubmit={handleProfileSubmit} className="space-y-4">
            <div>
              <label>Name</label>
              <input
                name="name"
                value={userInfo.name}
                onChange={handleProfileChange}
                className="mt-1 w-full border rounded-2xl px-4 py-2"
              />
            </div>
            <div>
              <label>Email</label>
              <input
                name="email"
                type="email"
                value={userInfo.email}
                onChange={handleProfileChange}
                className="mt-1 w-full border rounded-2xl px-4 py-2"
              />
            </div>
            <fieldset className="mt-4">
              <legend>Address</legend>
              {['street', 'city', 'country', 'postalCode'].map((field) => (
                <div key={field} className="mt-2">
                  <label className="capitalize">{field.replace('postalCode','Postal Code')}</label>
                  <input
                    name={`address.${field}`}
                    value={userInfo.address[field]}
                    onChange={handleProfileChange}
                    className="mt-1 w-full border rounded-2xl px-4 py-2"
                  />
                </div>
              ))}
            </fieldset>
            <button
              type="submit"
              disabled={savingProfile}
              className="mt-4 w-full py-2 rounded-2xl text-white bg-primary-600 hover:bg-primary-700 disabled:bg-neutral-400"
            >
              {savingProfile ? 'Saving…' : 'Save Profile'}
            </button>
          </form>
        </div>

        {/* Change Password */}
        <div className="bg-white rounded-2xl shadow-card p-6">
          <h2 className="text-2xl font-bold mb-4">Change Password</h2>
          <form onSubmit={handlePasswordSubmit} className="space-y-4">
            {['currentPassword','newPassword','confirmPassword'].map((field) => (
              <div key={field}>
                <label className="capitalize">{field.replace(/([A-Z])/g, ' $1')}</label>
                <input
                  name={field}
                  type="password"
                  value={passwordForm[field]}
                  onChange={handlePasswordChange}
                  className="mt-1 w-full border rounded-2xl px-4 py-2"
                />
              </div>
            ))}
            <button
              type="submit"
              disabled={changingPassword}
              className="mt-4 w-full py-2 rounded-2xl text-white bg-primary-600 hover:bg-primary-700 disabled:bg-neutral-400"
            >
              {changingPassword ? 'Updating…' : 'Change Password'}
            </button>
          </form>
        </div>
      </div>

      {/* Orders List */}
      <div className="bg-white rounded-2xl shadow-card p-6">
        <h2 className="text-2xl font-bold mb-4">My Orders</h2>
        {loadingOrders ? (
          <p>Loading orders…</p>
        ) : orders.length === 0 ? (
          <p>You have no orders yet.</p>
        ) : (
          <div className="space-y-4">
            {orders.map((order, idx) => (
              <motion.div
                key={order._id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.05 }}
                className="border rounded-2xl p-4 flex justify-between items-center"
              >
                <div>
                  <p className="font-semibold">Order ID: {order._id}</p>
                  <p>Status: {order.status.charAt(0).toUpperCase() + order.status.slice(1)}</p>
                  <p>Date: {new Date(order.createdAt).toLocaleString()}</p>
                  <p>Total: Tsh.{order.total.toFixed(2)}</p>
                </div>
                <button
                  onClick={() => confirmDeleteOrder(order._id)}
                  disabled={deletingId === order._id}
                  className="px-4 py-2 rounded-2xl text-white bg-red-600 hover:bg-red-700 disabled:bg-neutral-400"
                >
                  {deletingId === order._id ? 'Deleting…' : 'Delete'}
                </button>
              </motion.div>
            ))}
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        visible={Boolean(orderToDelete)}
        message="Are you sure you want to delete this order?"
        onConfirm={handleConfirmDelete}
        onCancel={handleCancelDelete}
      />
    </div>
  );
}
