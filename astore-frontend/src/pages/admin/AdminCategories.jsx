// src/pages/admin/AdminCategories.jsx

import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import api from '../../services/api';
import { toast } from 'react-toastify';
import { motion, AnimatePresence } from 'framer-motion';
import AnimatedButton from '../../components/AnimatedButton';
import { Trash2, Edit3 } from 'lucide-react';

export default function AdminCategories() {
  const [categories, setCategories] = useState([]);
  const [editingId, setEditingId] = useState(null);
  const [formData, setFormData] = useState({ name: '', description: '' });
  const [loading, setLoading] = useState(false);

  // For custom confirmation modal
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);

  // Fetch all categories
  const fetchCategories = async () => {
    try {
      const { data } = await api.get('/api/categories');
      setCategories(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error(err);
      toast.error('Failed to load categories.');
    }
  };

  useEffect(() => {
    fetchCategories();
  }, []);

  // Handle input changes
  const onChange = (e) => {
    setFormData((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  };

  // Start editing a category
  const startEdit = (cat) => {
    setEditingId(cat._id);
    setFormData({ name: cat.name || '', description: cat.description || '' });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Reset form (cancel editing)
  const resetForm = () => {
    setEditingId(null);
    setFormData({ name: '', description: '' });
  };

  // Submit new or updated category
  const onSubmit = async (e) => {
    e.preventDefault();
    if (!formData.name.trim()) {
      toast.error('Category name is required.');
      return;
    }

    setLoading(true);
    try {
      if (editingId) {
        // Update existing
        await api.put(`/api/categories/${editingId}`, {
          name: formData.name,
          description: formData.description,
        });
        toast.success('Category updated.');
      } else {
        // Create new
        await api.post('/api/categories', {
          name: formData.name,
          description: formData.description,
        });
        toast.success('Category created.');
      }
      resetForm();
      fetchCategories();
    } catch (err) {
      console.error(err);
      const msg =
        err.response?.data?.error ||
        err.response?.data?.errors?.map((e) => e.msg).join(', ') ||
        'Operation failed.';
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  // Trigger custom confirmation modal
  const confirmDeletion = (id) => {
    setConfirmDeleteId(id);
  };
  const cancelDeletion = () => {
    setConfirmDeleteId(null);
  };

  // Actually delete
  const handleDelete = async () => {
    const id = confirmDeleteId;
    if (!id) return;

    setDeletingId(id);
    try {
      await api.delete(`/api/categories/${id}`);
      toast.success('Category deleted.');
      if (editingId === id) resetForm();
      fetchCategories();
    } catch (err) {
      console.error(err);
      toast.error('Failed to delete category.');
    } finally {
      setDeletingId(null);
      setConfirmDeleteId(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Add / Edit Category Form */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white rounded-2xl shadow-card p-8"
      >
        <h3 className="text-xl font-medium text-neutral-800 mb-4">
          {editingId ? 'Edit Category' : 'Add New Category'}
        </h3>
        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <label htmlFor="name" className="block text-sm font-medium text-neutral-700">
              Name *
            </label>
            <input
              id="name"
              name="name"
              value={formData.name}
              onChange={onChange}
              required
              className="mt-1 block w-full border border-neutral-300 rounded-2xl px-3 py-2 bg-neutral-50 shadow-inner focus:outline-none focus:ring-2 focus:ring-primary-300"
            />
          </div>

          <div>
            <label htmlFor="description" className="block text-sm font-medium text-neutral-700">
              Description
            </label>
            <textarea
              id="description"
              name="description"
              value={formData.description}
              onChange={onChange}
              rows={3}
              className="mt-1 block w-full border border-neutral-300 rounded-2xl px-3 py-2 bg-neutral-50 shadow-inner focus:outline-none focus:ring-2 focus:ring-primary-300"
            />
          </div>

          <div className="flex space-x-4 mt-4">
            <AnimatedButton type="submit" className="px-6" disabled={loading}>
              {editingId
                ? loading
                  ? 'Updating…'
                  : 'Update'
                : loading
                ? 'Creating…'
                : 'Create'}
            </AnimatedButton>
            {editingId && (
              <button
                type="button"
                onClick={resetForm}
                className="px-6 py-2 border border-neutral-300 rounded-2xl text-neutral-700 hover:bg-neutral-100 focus:outline-none"
              >
                Cancel
              </button>
            )}
          </div>
        </form>
      </motion.div>

      {/* Categories List Table */}
      <div className="bg-neutral-50 p-8 rounded-2xl shadow-card">
        <h3 className="text-xl font-medium mb-4 text-neutral-800">All Categories</h3>
        {Array.isArray(categories) && categories.length > 0 ? (
          <div className="overflow-x-auto bg-white rounded-2xl shadow-card">
            <table className="min-w-full bg-transparent">
              <thead className="bg-neutral-100">
                <tr>
                  <th className="px-6 py-3 text-left text-sm font-medium text-neutral-600">Name</th>
                  <th className="px-6 py-3 text-left text-sm font-medium text-neutral-600">
                    Description
                  </th>
                  <th className="px-6 py-3 text-center text-sm font-medium text-neutral-600">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {categories.map((cat, idx) => (
                  <motion.tr
                    key={cat._id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="border-b even:bg-white hover:bg-neutral-100 transition-colors"
                  >
                    <td className="px-6 py-4 text-neutral-800">{cat.name}</td>
                    <td className="px-6 py-4 text-neutral-600">
                      {cat.description || '—'}
                    </td>
                    <td className="px-6 py-4 text-center space-x-4">
                      <button
                        onClick={() => startEdit(cat)}
                        className="text-blue-600 hover:text-blue-800 focus:outline-none"
                      >
                        <Edit3 size={18} />
                      </button>
                      <button
                        onClick={() => confirmDeletion(cat._id)}
                        className="text-red-600 hover:text-red-800 focus:outline-none"
                      >
                        <Trash2 size={18} />
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-center text-neutral-500 py-6">No categories found.</p>
        )}
      </div>

      {/* Custom Confirmation Modal via Portal */}
      {confirmDeleteId &&
        ReactDOM.createPortal(
          <AnimatePresence>
            <motion.div
              key="overlay"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
            >
              <motion.div
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.8, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="bg-white rounded-2xl p-6 w-80 text-center shadow-lg"
              >
                <p className="text-neutral-800 text-lg mb-4">
                  Are you sure you want to delete this category?
                </p>
                <div className="flex justify-center space-x-4">
                  <button
                    onClick={cancelDeletion}
                    className="px-4 py-2 bg-neutral-200 rounded-2xl hover:bg-neutral-300 transition text-sm"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleDelete}
                    disabled={deletingId === confirmDeleteId}
                    className="px-4 py-2 bg-red-500 text-white rounded-2xl hover:bg-red-600 transition text-sm"
                  >
                    {deletingId === confirmDeleteId ? 'Deleting…' : 'Delete'}
                  </button>
                </div>
              </motion.div>
            </motion.div>
          </AnimatePresence>,
          document.body
        )}
    </div>
  );
}
