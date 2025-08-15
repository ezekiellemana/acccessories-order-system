// src/pages/admin/AdminReviews.jsx
import React, { useEffect, useState, useRef } from 'react'
import ReactDOM from 'react-dom'
import { toast } from 'react-toastify'
import api from '../../services/api'
import { FaTrash, FaStar, FaSort, FaSortUp, FaSortDown } from 'react-icons/fa'
import { motion, AnimatePresence } from 'framer-motion'
import AnimatedButton from '../../components/AnimatedButton'

export default function AdminReviews() {
  // raw data
  const [reviews, setReviews] = useState([])
  const [loading, setLoading] = useState(true)

  // filters
  const [searchTerm, setSearchTerm] = useState('')
  const [ratingFilter, setRatingFilter] = useState('all') // 'all' or '5','4',...
  const [startDate, setStartDate] = useState('') // '' means no filter
  const [endDate, setEndDate] = useState('')

  // sorting
  const [sortBy, setSortBy] = useState('createdAt') // 'createdAt' or 'rating'
  const [sortDir, setSortDir] = useState('desc') // 'asc' or 'desc'

  // pagination
  const [currentPage, setCurrentPage] = useState(1)
  const reviewsPerPage = 10

  // bulk selection
  const [selectedIds, setSelectedIds] = useState(new Set())

  // single delete
  const [confirmDeleteId, setConfirmDeleteId] = useState(null)
  const [deletingId, setDeletingId] = useState(null)

  // bulk delete
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false)
  const [bulkDeleting, setBulkDeleting] = useState(false)

  // CSV export util
  const exportCSV = (data, cols, filename) => {
    if (!data.length) return toast.error('No data to export')
    const header = cols.map(c => c.label).join(',') + '\n'
    const rows = data
      .map(r => cols.map(c => `"${(r[c.key] ?? '').toString().replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename + '.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const fetchAll = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/admin/reviews')
      setReviews(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error(err)
      toast.error('Could not load reviews.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAll()
  }, [])

  // filter logic
  const filtered = reviews
    .filter(r => {
      // search in user name/email & product name
      const term = searchTerm.trim().toLowerCase()
      if (term) {
        const inUser = r.user?.name?.toLowerCase().includes(term) ||
                       r.user?.email?.toLowerCase().includes(term)
        const inProd = r.product?.name?.toLowerCase().includes(term)
        if (!inUser && !inProd) return false
      }
      // rating filter
      if (ratingFilter !== 'all' && r.rating !== Number(ratingFilter)) return false
      // date filter
      const created = new Date(r.createdAt).toISOString().split('T')[0]
      if (startDate && created < startDate) return false
      if (endDate && created > endDate) return false
      return true
    })
    // sort
    .sort((a, b) => {
      const dir = sortDir === 'asc' ? 1 : -1
      if (sortBy === 'rating') return dir * (a.rating - b.rating)
      // date
      return dir * (new Date(a.createdAt) - new Date(b.createdAt))
    })

  // pagination
  const totalPages = Math.ceil(filtered.length / reviewsPerPage) || 1
  const startIdx = (currentPage - 1) * reviewsPerPage
  const currentReviews = filtered.slice(startIdx, startIdx + reviewsPerPage)

  // handlers
  const toggleSort = (col) => {
    if (sortBy === col) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(col)
      setSortDir('asc')
    }
  }

  const toggleSelect = (id) => {
    const s = new Set(selectedIds)
    s.has(id) ? s.delete(id) : s.add(id)
    setSelectedIds(s)
  }

  const selectAllOnPage = (chk) => {
    const s = new Set(selectedIds)
    currentReviews.forEach(r => {
      if (chk) s.add(r._id)
      else s.delete(r._id)
    })
    setSelectedIds(s)
  }

  const confirmDeletion = (id) => setConfirmDeleteId(id)
  const cancelDeletion = () => setConfirmDeleteId(null)

  const handleDelete = async () => {
    const id = confirmDeleteId
    if (!id) return
    setDeletingId(id)
    try {
      await api.delete(`/api/reviews/${id}`)
      toast.success('Review deleted.')
      setReviews(prev => prev.filter(r => r._id !== id))
      setSelectedIds(prev => { const s = new Set(prev); s.delete(id); return s })
    } catch (err) {
      console.error(err)
      toast.error('Could not delete review.')
    } finally {
      setDeletingId(null)
      setConfirmDeleteId(null)
    }
  }

  const confirmBulk = () => setConfirmBulkDelete(true)
  const cancelBulk = () => setConfirmBulkDelete(false)

  const handleBulkDelete = async () => {
    setBulkDeleting(true)
    try {
      await Promise.all(Array.from(selectedIds).map(id => api.delete(`/api/reviews/${id}`)))
      toast.success(`${selectedIds.size} review(s) deleted.`)
      setReviews(prev => prev.filter(r => !selectedIds.has(r._id)))
      setSelectedIds(new Set())
    } catch (err) {
      console.error(err)
      toast.error('Bulk delete failed.')
    } finally {
      setBulkDeleting(false)
      setConfirmBulkDelete(false)
    }
  }

  if (loading) {
    return <p className="text-neutral-500">Loading reviews…</p>
  }

  return (
    <div className="space-y-4 p-6 bg-white rounded-2xl shadow-card">
      <h3 className="text-2xl font-semibold text-neutral-800">Review Management</h3>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Search user or product…"
          value={searchTerm}
          onChange={e => { setSearchTerm(e.target.value); setCurrentPage(1) }}
          className="px-3 py-2 border rounded-2xl flex-1 min-w-[200px]"
        />
        <select
          value={ratingFilter}
          onChange={e => { setRatingFilter(e.target.value); setCurrentPage(1) }}
          className="px-3 py-2 border rounded-2xl"
        >
          <option value="all">All Ratings</option>
          {[5,4,3,2,1].map(n => (
            <option key={n} value={n}>{'★'.repeat(n)}</option>
          ))}
        </select>
        <input
          type="date"
          value={startDate}
          onChange={e => { setStartDate(e.target.value); setCurrentPage(1) }}
          className="px-3 py-2 border rounded-2xl"
        />
        <input
          type="date"
          value={endDate}
          onChange={e => { setEndDate(e.target.value); setCurrentPage(1) }}
          className="px-3 py-2 border rounded-2xl"
        />
        <AnimatedButton
          onClick={fetchAll}
          className="px-4 py-2 bg-purple-600 text-white rounded-2xl hover:bg-purple-700 no-print"
        >
          Refresh
        </AnimatedButton>
      </div>

      {/* Bulk actions */}
      <div className="flex items-center gap-2 no-print">
        <label className="inline-flex items-center">
          <input
            type="checkbox"
            checked={currentReviews.every(r => selectedIds.has(r._id))}
            onChange={e => selectAllOnPage(e.target.checked)}
            className="mr-2"
          />
          Select All on Page
        </label>
        <AnimatedButton
          onClick={confirmBulk}
          disabled={!selectedIds.size}
          className="px-4 py-2 bg-red-500 text-white rounded-2xl hover:bg-red-600"
        >
          Delete Selected ({selectedIds.size})
        </AnimatedButton>
        <AnimatedButton
          onClick={() =>
            exportCSV(
              currentReviews.map(r => ({
                id: r._id,
                product: r.product?.name || '',
                user: r.user?.name || '',
                rating: r.rating,
                date: new Date(r.createdAt).toISOString(),
                comment: r.comment,
              })),
              [
                { key: 'id', label: 'Review ID' },
                { key: 'product', label: 'Product' },
                { key: 'user', label: 'User' },
                { key: 'rating', label: 'Rating' },
                { key: 'date', label: 'Date' },
                { key: 'comment', label: 'Comment' },
              ],
              'reviews_export'
            )
          }
          className="px-4 py-2 bg-green-600 text-white rounded-2xl hover:bg-green-700"
        >
          Export CSV
        </AnimatedButton>
      </div>

      {/* Reviews Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full text-left">
          <thead className="bg-neutral-100 sticky top-0 z-10">
            <tr>
              <th className="px-4 py-2">{/* checkbox col */}</th>
              <th className="px-4 py-2">Product</th>
              <th className="px-4 py-2">User</th>
              <th
                className="px-4 py-2 cursor-pointer select-none"
                onClick={() => toggleSort('rating')}
              >
                Rating{' '}
                {sortBy === 'rating' ? (
                  sortDir === 'asc' ? <FaSortUp /> : <FaSortDown />
                ) : <FaSort />}
              </th>
              <th className="px-4 py-2">Comment</th>
              <th
                className="px-4 py-2 cursor-pointer select-none"
                onClick={() => toggleSort('createdAt')}
              >
                Date{' '}
                {sortBy === 'createdAt' ? (
                  sortDir === 'asc' ? <FaSortUp /> : <FaSortDown />
                ) : <FaSort />}
              </th>
              <th className="px-4 py-2">Action</th>
            </tr>
          </thead>
          <tbody>
            {currentReviews.map((r, i) => (
              <motion.tr
                key={r._id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.02 }}
                className="border-b even:bg-neutral-50 hover:bg-neutral-100"
              >
                <td className="px-4 py-2">
                  <input
                    type="checkbox"
                    checked={selectedIds.has(r._id)}
                    onChange={() => toggleSelect(r._id)}
                  />
                </td>
                <td className="px-4 py-2 break-words">{r.product?.name || '—'}</td>
                <td className="px-4 py-2 break-words">{r.user?.name || 'Anonymous'}</td>
                <td className="px-4 py-2">
                  <div className="flex items-center space-x-1">
                    {[...Array(5)].map((_, idx) => (
                      <FaStar
                        key={idx}
                        className={idx < r.rating ? 'text-yellow-500' : 'text-neutral-300'}
                      />
                    ))}
                  </div>
                </td>
                <td className="px-4 py-2 break-words">{r.comment || '—'}</td>
                <td className="px-4 py-2 whitespace-nowrap">
                  {new Date(r.createdAt).toLocaleDateString()}
                </td>
                <td className="px-4 py-2">
                  <AnimatedButton
                    onClick={() => confirmDeletion(r._id)}
                    disabled={deletingId === r._id}
                    className="px-3 py-1 bg-red-500 text-white rounded-2xl hover:bg-red-600"
                  >
                    <FaTrash />
                  </AnimatedButton>
                </td>
              </motion.tr>
            ))}
            {currentReviews.length === 0 && (
              <tr>
                <td colSpan="7" className="py-6 text-center text-neutral-500">
                  No reviews match.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center space-x-2 mt-4">
          <AnimatedButton
            onClick={() => setCurrentPage(p => Math.max(p - 1, 1))}
            disabled={currentPage === 1}
            className="px-3 py-1 border rounded-2xl"
          >
            Prev
          </AnimatedButton>
          {[...Array(totalPages)].map((_, idx) => (
            <AnimatedButton
              key={idx}
              onClick={() => setCurrentPage(idx + 1)}
              className={`px-3 py-1 border rounded-2xl ${
                currentPage === idx + 1 ? 'bg-purple-600 text-white' : ''
              }`}
            >
              {idx + 1}
            </AnimatedButton>
          ))}
          <AnimatedButton
            onClick={() => setCurrentPage(p => Math.min(p + 1, totalPages))}
            disabled={currentPage === totalPages}
            className="px-3 py-1 border rounded-2xl"
          >
            Next
          </AnimatedButton>
        </div>
      )}

      {/* Single Delete Modal */}
      {confirmDeleteId &&
        ReactDOM.createPortal(
          <AnimatePresence>
            <motion.div
              key="overlay-single"
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
                  Delete this review?
                </p>
                <div className="flex justify-center space-x-4">
                  <button
                    onClick={cancelDeletion}
                    className="px-4 py-2 bg-neutral-200 rounded-2xl hover:bg-neutral-300"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleDelete}
                    disabled={deletingId === confirmDeleteId}
                    className="px-4 py-2 bg-red-500 text-white rounded-2xl hover:bg-red-600"
                  >
                    {deletingId === confirmDeleteId ? 'Deleting…' : 'Delete'}
                  </button>
                </div>
              </motion.div>
            </motion.div>
          </AnimatePresence>,
          document.body
        )}

      {/* Bulk Delete Modal */}
      {confirmBulkDelete &&
        ReactDOM.createPortal(
          <AnimatePresence>
            <motion.div
              key="overlay-bulk"
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
                  Delete {selectedIds.size} selected review(s)?
                </p>
                <div className="flex justify-center space-x-4">
                  <button
                    onClick={cancelBulk}
                    className="px-4 py-2 bg-neutral-200 rounded-2xl hover:bg-neutral-300"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleBulkDelete}
                    disabled={bulkDeleting}
                    className="px-4 py-2 bg-red-500 text-white rounded-2xl hover:bg-red-600"
                  >
                    {bulkDeleting ? 'Deleting…' : 'Delete All'}
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
