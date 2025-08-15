// src/pages/admin/AdminOrders.jsx
import React, { useEffect, useState, useRef } from 'react'
import ReactDOM from 'react-dom'
import api from '../../services/api'
import { toast } from 'react-toastify'
import { motion, AnimatePresence } from 'framer-motion'
import AnimatedButton from '../../components/AnimatedButton'

export default function AdminOrders() {
  const [orders, setOrders] = useState([])
  const [loading, setLoading] = useState(true)
  const [updatingId, setUpdatingId] = useState(null)
  const [deletingId, setDeletingId] = useState(null)
  const [confirmCompleteId, setConfirmCompleteId] = useState(null)
  const [confirmDeleteId, setConfirmDeleteId] = useState(null)

  // filters & pagination
  const [filterTerm, setFilterTerm] = useState('')
  const [filterStatus, setFilterStatus] = useState('all')
  const [currentPage, setCurrentPage] = useState(1)
  const ordersPerPage = 10
  const firstMount = useRef(true)

  // fetch orders
  const fetchOrders = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/admin/orders', {
        params: { limit: 1000, sort: 'createdAt_desc' },
      })
      setOrders(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error(err)
      toast.error('Could not load orders.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchOrders()
  }, [])

  // reset page when filters change (skip first mount)
  useEffect(() => {
    if (firstMount.current) {
      firstMount.current = false
      return
    }
    setCurrentPage(1)
  }, [filterTerm, filterStatus])

  // filtered list
  const filtered = orders.filter((o) => {
    const term = filterTerm.trim().toLowerCase()
    const matchesTerm =
      o._id.includes(term) ||
      o.user.email.toLowerCase().includes(term) ||
      o.user.name.toLowerCase().includes(term)
    const matchesStatus =
      filterStatus === 'all' || o.status === filterStatus
    return matchesTerm && matchesStatus
  })

  const totalPages = Math.ceil(filtered.length / ordersPerPage)
  const startIdx = (currentPage - 1) * ordersPerPage
  const currentOrders = filtered.slice(startIdx, startIdx + ordersPerPage)

  // paginate handlers
  const prevPage = () => setCurrentPage((p) => Math.max(p - 1, 1))
  const nextPage = () => setCurrentPage((p) => Math.min(p + 1, totalPages))

  // confirm/cancel
  const confirmComplete = (id) => setConfirmCompleteId(id)
  const cancelComplete = () => setConfirmCompleteId(null)
  const confirmDelete = (id) => setConfirmDeleteId(id)
  const cancelDelete = () => setConfirmDeleteId(null)

  // mark completed
  const handleMarkCompleted = async () => {
    const id = confirmCompleteId
    if (!id) return
    setUpdatingId(id)
    try {
      await api.put(`/api/admin/orders/${id}`, { status: 'completed' })
      toast.success('Order marked completed.')
      await fetchOrders()
    } catch (err) {
      console.error(err)
      toast.error('Could not update order.')
    } finally {
      setUpdatingId(null)
      setConfirmCompleteId(null)
    }
  }

  // delete order
  const handleDeleteOrder = async () => {
    const id = confirmDeleteId
    if (!id) return
    setDeletingId(id)
    try {
      await api.delete(`/api/admin/orders/${id}`)
      toast.success('Order deleted.')
      setOrders((prev) => prev.filter((o) => o._id !== id))
    } catch (err) {
      console.error(err)
      toast.error('Could not delete order.')
    } finally {
      setDeletingId(null)
      setConfirmDeleteId(null)
    }
  }

  if (loading) {
    return <p className="text-neutral-500">Loading orders…</p>
  }

  return (
    <div className="p-6 space-y-6">
      <h2 className="text-2xl font-bold text-neutral-800">Manage Orders</h2>

      {/* Filters */}
      <div className="flex flex-col md:flex-row items-start md:items-center gap-4">
        <input
          type="text"
          placeholder="Search by ID, name or email…"
          value={filterTerm}
          onChange={(e) => setFilterTerm(e.target.value)}
          className="w-full md:w-1/3 px-4 py-2 border rounded-2xl focus:outline-none focus:ring-2 focus:ring-primary-400"
        />
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="px-4 py-2 border rounded-2xl focus:outline-none focus:ring-2 focus:ring-primary-400"
        >
          <option value="all">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="completed">Completed</option>
          <option value="cancelled">Cancelled</option>
        </select>
      </div>

      {/* Orders Table */}
      <div className="overflow-x-auto bg-white rounded-2xl shadow-card">
        <table className="min-w-full">
          <thead className="bg-neutral-100 sticky top-0">
            <tr>
              <th className="px-6 py-3 text-left text-sm font-medium text-neutral-600">Order ID</th>
              <th className="px-6 py-3 text-left text-sm font-medium text-neutral-600">User</th>
              <th className="px-6 py-3 text-left text-sm font-medium text-neutral-600">Date</th>
              <th className="px-6 py-3 text-right text-sm font-medium text-neutral-600">Total</th>
              <th className="px-6 py-3 text-center text-sm font-medium text-neutral-600">Status</th>
              <th className="px-6 py-3 text-right text-sm font-medium text-neutral-600">Actions</th>
            </tr>
          </thead>
          <tbody>
            {currentOrders.map((order, idx) => (
              <motion.tr
                key={order._id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.03 }}
                className="border-b even:bg-neutral-50 hover:bg-neutral-100 transition-colors"
              >
                <td className="px-6 py-4 text-sm break-words">{order._id}</td>
                <td className="px-6 py-4 text-sm break-words">
                  {order.user.name} ({order.user.email})
                </td>
                <td className="px-6 py-4 text-sm whitespace-nowrap">
                  {new Date(order.createdAt).toLocaleDateString()}{' '}
                  {new Date(order.createdAt).toLocaleTimeString()}
                </td>
                <td className="px-6 py-4 text-right text-sm whitespace-nowrap">
                  Tsh.{order.total.toFixed(2)}
                </td>
                <td className="px-6 py-4 text-center text-sm">
                  <span
                    className={`font-medium ${
                      order.status === 'completed'
                        ? 'text-green-600'
                        : order.status === 'cancelled'
                        ? 'text-red-600'
                        : 'text-yellow-600'
                    }`}
                  >
                    {order.status.charAt(0).toUpperCase() + order.status.slice(1)}
                  </span>
                </td>
                <td className="px-6 py-4 text-right space-x-2">
                  {order.status === 'pending' && (
                    <AnimatedButton
                      onClick={() => confirmComplete(order._id)}
                      disabled={updatingId === order._id}
                      className="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded-2xl text-sm"
                    >
                      {updatingId === order._id ? 'Updating…' : 'Mark Completed'}
                    </AnimatedButton>
                  )}
                  <AnimatedButton
                    onClick={() => confirmDelete(order._id)}
                    disabled={deletingId === order._id}
                    className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded-2xl text-sm"
                  >
                    {deletingId === order._id ? 'Deleting…' : 'Delete'}
                  </AnimatedButton>
                </td>
              </motion.tr>
            ))}

            {currentOrders.length === 0 && (
              <tr>
                <td colSpan="6" className="py-6 text-center text-neutral-500">
                  No orders found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center mt-4">
          <button
            onClick={prevPage}
            disabled={currentPage === 1}
            className="px-3 py-1 border rounded-2xl mr-1 disabled:opacity-50 hover:bg-neutral-100"
          >
            Prev
          </button>
          {[...Array(totalPages)].map((_, i) => (
            <button
              key={i}
              onClick={() => setCurrentPage(i + 1)}
              className={`px-3 py-1 border rounded-2xl mx-1 ${
                currentPage === i + 1
                  ? 'bg-primary-600 text-white border-primary-600'
                  : 'hover:bg-neutral-100'
              }`}
            >
              {i + 1}
            </button>
          ))}
          <button
            onClick={nextPage}
            disabled={currentPage === totalPages}
            className="px-3 py-1 border rounded-2xl ml-1 disabled:opacity-50 hover:bg-neutral-100"
          >
            Next
          </button>
        </div>
      )}

      {/* Confirm Complete Modal */}
      {confirmCompleteId &&
        ReactDOM.createPortal(
          <AnimatePresence>
            <motion.div
              key="overlay-complete"
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
                  Mark this order as completed?
                </p>
                <div className="flex justify-center space-x-4">
                  <button
                    onClick={cancelComplete}
                    className="px-4 py-2 bg-neutral-200 rounded-2xl hover:bg-neutral-300 transition text-sm"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleMarkCompleted}
                    disabled={updatingId === confirmCompleteId}
                    className="px-4 py-2 bg-green-600 text-white rounded-2xl hover:bg-green-700 transition text-sm"
                  >
                    {updatingId === confirmCompleteId ? 'Updating…' : 'Confirm'}
                  </button>
                </div>
              </motion.div>
            </motion.div>
          </AnimatePresence>,
          document.body
        )}

      {/* Confirm Delete Modal */}
      {confirmDeleteId &&
        ReactDOM.createPortal(
          <AnimatePresence>
            <motion.div
              key="overlay-delete"
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
                  Delete this order permanently?
                </p>
                <div className="flex justify-center space-x-4">
                  <button
                    onClick={cancelDelete}
                    className="px-4 py-2 bg-neutral-200 rounded-2xl hover:bg-neutral-300 transition text-sm"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleDeleteOrder}
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
  )
}
