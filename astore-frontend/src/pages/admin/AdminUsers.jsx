// src/pages/admin/AdminUsers.jsx
import React, { useEffect, useState, useRef } from 'react'
import ReactDOM from 'react-dom'
import api from '../../services/api'
import { motion, AnimatePresence } from 'framer-motion'
import { toast } from 'react-toastify'
import AnimatedButton from '../../components/AnimatedButton'
import { Trash2, ShieldOff, Shield } from 'lucide-react'

export default function AdminUsers() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [confirmDeleteId, setConfirmDeleteId] = useState(null)
  const [deletingId, setDeletingId] = useState(null)

  // pagination & filters
  const [currentPage, setCurrentPage] = useState(1)
  const usersPerPage = 10
  const [filterTerm, setFilterTerm] = useState('')
  const [filterRole, setFilterRole] = useState('all')
  const firstRender = useRef(true)

  // fetch all users once
  const fetchUsers = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/users')
      setUsers(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error(err)
      toast.error('Failed to load users.')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => {
    fetchUsers()
  }, [])

  // reset page when filters change (skip first render)
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false
      return
    }
    setCurrentPage(1)
  }, [filterTerm, filterRole])

  // apply search + role filter
  const filteredUsers = users.filter((u) => {
    const termMatch =
      u.name.toLowerCase().includes(filterTerm.toLowerCase()) ||
      u.email.toLowerCase().includes(filterTerm.toLowerCase())
    const roleMatch =
      filterRole === 'all' ||
      (filterRole === 'admin' && u.isAdmin) ||
      (filterRole === 'user' && !u.isAdmin)
    return termMatch && roleMatch
  })

  const totalPages = Math.ceil(filteredUsers.length / usersPerPage)
  const startIdx = (currentPage - 1) * usersPerPage
  const currentUsers = filteredUsers.slice(startIdx, startIdx + usersPerPage)

  // deletion flow
  const confirmDeletion = (id) => setConfirmDeleteId(id)
  const cancelDeletion = () => setConfirmDeleteId(null)

  const handleDelete = async () => {
    const id = confirmDeleteId
    if (!id) return
    setDeletingId(id)
    try {
      await api.delete(`/api/users/${id}`)
      toast.success('User deleted.')
      await fetchUsers()
    } catch (err) {
      console.error(err)
      toast.error('Failed to delete user.')
    } finally {
      setDeletingId(null)
      setConfirmDeleteId(null)
    }
  }

  // toggle admin role
  const toggleAdmin = async (id, isAdmin) => {
    try {
      await api.put(`/api/users/${id}`, { isAdmin: !isAdmin })
      toast.success('User role updated.')
      fetchUsers()
    } catch (err) {
      console.error(err)
      toast.error('Failed to update user.')
    }
  }

  if (loading) {
    return <p className="text-neutral-500">Loading users…</p>
  }

  return (
    <div className="space-y-6">
      <h3 className="text-xl font-medium text-neutral-800">User Management</h3>

      {/* filters */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <input
          type="text"
          placeholder="Search by name or email…"
          value={filterTerm}
          onChange={(e) => setFilterTerm(e.target.value)}
          className="w-full md:w-1/3 border border-neutral-300 rounded-2xl px-4 py-2 focus:outline-none focus:ring-2 focus:ring-accent-400"
        />
        <select
          value={filterRole}
          onChange={(e) => setFilterRole(e.target.value)}
          className="border border-neutral-300 rounded-2xl px-4 py-2 focus:outline-none focus:ring-2 focus:ring-accent-400"
        >
          <option value="all">All Roles</option>
          <option value="admin">Admins Only</option>
          <option value="user">Users Only</option>
        </select>
      </div>

      <div className="bg-neutral-50 p-6 rounded-2xl shadow-card">
        <div className="overflow-x-auto bg-white rounded-2xl shadow-inner">
          <table className="min-w-full">
            <thead className="bg-neutral-100 sticky top-0">
              <tr>
                <th className="px-6 py-3 text-left text-sm font-medium text-neutral-600">Name</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-neutral-600">Email</th>
                <th className="px-6 py-3 text-center text-sm font-medium text-neutral-600">Role</th>
                <th className="px-6 py-3 text-right text-sm font-medium text-neutral-600">Actions</th>
              </tr>
            </thead>
            <tbody>
              {currentUsers.map((usr, idx) => (
                <motion.tr
                  key={usr._id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  className="border-b even:bg-neutral-50 hover:bg-neutral-100 transition-colors"
                >
                  <td className="px-6 py-4 text-neutral-800 break-words">{usr.name}</td>
                  <td className="px-6 py-4 text-neutral-600 break-words">{usr.email}</td>
                  <td className="px-6 py-4 text-center">
                    {usr.isAdmin ? (
                      <Shield size={18} className="text-green-600 mx-auto" />
                    ) : (
                      <ShieldOff size={18} className="text-red-600 mx-auto" />
                    )}
                  </td>
                  <td className="px-6 py-4 text-right space-x-2">
                    <AnimatedButton
                      onClick={() => toggleAdmin(usr._id, usr.isAdmin)}
                      className="text-sm px-4"
                    >
                      {usr.isAdmin ? 'Revoke Admin' : 'Make Admin'}
                    </AnimatedButton>
                    <button
                      onClick={() => confirmDeletion(usr._id)}
                      className="text-red-500 hover:text-red-700 focus:outline-none"
                    >
                      <Trash2 size={18} />
                    </button>
                  </td>
                </motion.tr>
              ))}

              {currentUsers.length === 0 && (
                <tr>
                  <td colSpan="4" className="py-6 text-center text-neutral-500">
                    No users match your criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* pagination */}
        {totalPages > 1 && (
          <div className="flex justify-center mt-4">
            <ul className="inline-flex items-center space-x-1">
              <li>
                <button
                  onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 border rounded-2xl disabled:opacity-50 hover:bg-neutral-100"
                >
                  Prev
                </button>
              </li>
              {[...Array(totalPages)].map((_, idx) => (
                <li key={idx}>
                  <button
                    onClick={() => setCurrentPage(idx + 1)}
                    className={`px-3 py-1 border rounded-2xl ${
                      currentPage === idx + 1
                        ? 'bg-primary-600 text-white border-primary-600'
                        : 'hover:bg-neutral-100'
                    }`}
                  >
                    {idx + 1}
                  </button>
                </li>
              ))}
              <li>
                <button
                  onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 border rounded-2xl disabled:opacity-50 hover:bg-neutral-100"
                >
                  Next
                </button>
              </li>
            </ul>
          </div>
        )}
      </div>

      {/* delete confirmation */}
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
                  Are you sure you want to delete this user?
                </p>
                <div className="flex justify-center space-x-4">
                  <button
                    onClick={cancelDeletion}
                    className="px-4 py-2 bg-neutral-200 rounded-2xl hover:bg-neutral-300 transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleDelete}
                    disabled={deletingId === confirmDeleteId}
                    className="px-4 py-2 bg-red-500 text-white rounded-2xl hover:bg-red-600 transition"
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
  )
}
