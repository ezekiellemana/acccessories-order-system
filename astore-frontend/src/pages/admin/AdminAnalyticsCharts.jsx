// src/pages/admin/AdminAnalyticsCharts.jsx
import React, { useEffect, useState, useRef } from 'react'
import api from '../../services/api'
import { toast } from 'react-toastify'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid,
  BarChart, Bar, PieChart, Pie, Cell, Legend, ResponsiveContainer
} from 'recharts'
import { motion } from 'framer-motion'
import AnimatedButton from '../../components/AnimatedButton'

export default function AdminAnalyticsCharts() {
  // 1) Summary counts
  const [counts, setCounts] = useState(null)
  // 2) Sales data + date filters
  const [salesData, setSalesData] = useState([])
  const [startDate, setStartDate] = useState(() => {
    const d = new Date()
    d.setDate(d.getDate() - 30)
    return d.toISOString().split('T')[0]
  })
  const [endDate, setEndDate] = useState(() => new Date().toISOString().split('T')[0])
  // 3) Top products
  const [topProducts, setTopProducts] = useState([])
  // 4) Category sales
  const [categorySales, setCategorySales] = useState([])
  // 5) Recent orders
  const [recentOrders, setRecentOrders] = useState([])
  // 6) Top customers
  const [topCustomers, setTopCustomers] = useState([])
  // 7) Low‐stock alerts + threshold
  const [lowInventory, setLowInventory] = useState([])
  const [threshold, setThreshold] = useState(10)

  // loading state for “Refresh Data”
  const [loadingAll, setLoadingAll] = useState(false)
  const firstMount = useRef(true)

  const COLORS = ['#7C3AED', '#A78BFA', '#C084FC', '#DDD6FE', '#EDE9FE']

  // util: export array of objects to CSV
  const exportCSV = (data, columns, filename) => {
    if (!data || !data.length) {
      toast.error('No data to export.')
      return
    }
    const header = columns.map((c) => c.label).join(',') + '\n'
    const rows = data
      .map((row) =>
        columns
          .map((c) => {
            const v = row[c.key]
            // escape quotes
            return `"${(v ?? '').toString().replace(/"/g, '""')}"`
          })
          .join(',')
      )
      .join('\n')
    const csv = header + rows
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename + '.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  // fetchers
  const fetchCounts = async () => {
    try {
      const { data } = await api.get('/api/admin/analytics/counts')
      setCounts(data)
    } catch (err) {
      console.error(err)
      toast.error('Failed to load summary counts.')
      setCounts({ users: 0, products: 0, orders: 0, reviews: 0 })
    }
  }
  const fetchSales = async () => {
    try {
      const { data } = await api.get('/api/admin/analytics/sales', {
        params: { start: startDate, end: endDate },
      })
      setSalesData(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error(err)
      toast.error('Failed to load sales data.')
      setSalesData([])
    }
  }
  const fetchTopProducts = async () => {
    try {
      const { data } = await api.get('/api/admin/analytics/top-products', {
        params: { limit: 5, start: startDate, end: endDate },
      })
      setTopProducts(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error(err)
      toast.error('Failed to load top products.')
      setTopProducts([])
    }
  }
  const fetchCategorySales = async () => {
    try {
      const { data } = await api.get('/api/admin/analytics/category-sales')
      setCategorySales(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error(err)
      toast.error('Failed to load category sales.')
      setCategorySales([])
    }
  }
  const fetchRecentOrders = async () => {
    try {
      const { data } = await api.get('/api/admin/orders', {
        params: { limit: 5, sort: 'createdAt_desc' },
      })
      setRecentOrders(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error(err)
      toast.error('Failed to load recent orders.')
      setRecentOrders([])
    }
  }
  const fetchTopCustomers = async () => {
    try {
      const { data } = await api.get('/api/admin/analytics/top-customers', {
        params: { limit: 5 },
      })
      setTopCustomers(data?.customers ?? [])
    } catch (err) {
      console.error(err)
      toast.error('Failed to load top customers.')
      setTopCustomers([])
    }
  }
  const fetchLowInventory = async () => {
    try {
      const { data } = await api.get('/api/admin/analytics/low-stock', {
        params: { threshold },
      })
      setLowInventory(data?.products ?? [])
    } catch (err) {
      console.error(err)
      toast.error('Failed to load low-stock alerts.')
      setLowInventory([])
    }
  }

  // run all
  const fetchAll = async () => {
    setLoadingAll(true)
    await Promise.all([
      fetchCounts(),
      fetchSales(),
      fetchTopProducts(),
      fetchCategorySales(),
      fetchRecentOrders(),
      fetchTopCustomers(),
      fetchLowInventory(),
    ])
    setLoadingAll(false)
  }

  // on mount + when range or threshold changes
  useEffect(() => {
    if (firstMount.current) {
      firstMount.current = false
      fetchAll()
    } else {
      fetchAll()
    }
  }, [startDate, endDate, threshold])

  const totalSalesRange = salesData.reduce((sum, e) => sum + (e.totalSales || 0), 0)

  // for printing
  const handlePrint = () => {
    const prev = document.title
    document.title = `Analytics_${startDate}_to_${endDate}`
    window.print()
    document.title = prev
  }

  // presets
  const applyPreset = (days) => {
    const now = new Date()
    const start = new Date()
    start.setDate(now.getDate() - days)
    setStartDate(start.toISOString().split('T')[0])
    setEndDate(now.toISOString().split('T')[0])
  }

  return (
    <div className="p-6 space-y-8 max-w-full">
      {/* Controls */}
      <div className="flex flex-wrap gap-2 justify-end no-print">
        <AnimatedButton
          onClick={fetchAll}
          disabled={loadingAll}
          className="px-4 py-2 bg-purple-600 text-white rounded-2xl hover:bg-purple-700"
        >
          {loadingAll ? 'Refreshing…' : 'Refresh Data'}
        </AnimatedButton>
        <AnimatedButton
          onClick={handlePrint}
          className="px-4 py-2 bg-purple-500 text-white rounded-2xl hover:bg-purple-600"
        >
          Print Report
        </AnimatedButton>
      </div>

      {/* Date range & threshold */}
      <div className="flex flex-wrap gap-4 items-center no-print">
        <div className="flex items-center gap-2">
          <label htmlFor="preset-7" className="text-purple-700 font-medium cursor-pointer">
            Preset:
          </label>
          <button
            id="preset-7"
            onClick={() => applyPreset(7)}
            className="px-3 py-1 bg-purple-200 rounded-2xl hover:bg-purple-300"
          >
            Last 7d
          </button>
          <button
            onClick={() => applyPreset(30)}
            className="px-3 py-1 bg-purple-200 rounded-2xl hover:bg-purple-300"
          >
            Last 30d
          </button>
        </div>
        <div className="flex items-center gap-2">
          <label htmlFor="start-date" className="text-purple-700 font-medium">
            From
          </label>
          <input
            id="start-date"
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            className="px-3 py-2 border rounded-2xl focus:ring-2 focus:ring-purple-300"
          />
        </div>
        <div className="flex items-center gap-2">
          <label htmlFor="end-date" className="text-purple-700 font-medium">
            To
          </label>
          <input
            id="end-date"
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            className="px-3 py-2 border rounded-2xl focus:ring-2 focus:ring-purple-300"
          />
        </div>
        <div className="flex items-center gap-2">
          <label htmlFor="threshold" className="text-purple-700 font-medium">
            Low‐stock ≤
          </label>
          <input
            id="threshold"
            type="number"
            min="0"
            value={threshold}
            onChange={(e) => setThreshold(parseInt(e.target.value, 10))}
            className="w-20 px-3 py-2 border rounded-2xl focus:ring-2 focus:ring-purple-300"
          />
        </div>
      </div>

      {/* Summary counts */}
      {counts && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {[
            { label: 'Users', value: counts.users, color: 'purple-600' },
            { label: 'Products', value: counts.products, color: 'purple-500' },
            { label: 'Orders', value: counts.orders, color: 'purple-400' },
            {
              label: 'Sales in Range',
              value: totalSalesRange.toLocaleString(),
              color: 'purple-300',
            },
          ].map((c, i) => (
            <motion.div
              key={c.label}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className={`bg-purple-50 border-l-4 border-${c.color} rounded-2xl p-6 shadow-card`}
            >
              <p className="text-sm text-purple-700">{`Total ${c.label}`}</p>
              <p className={`mt-1 text-2xl font-bold text-${c.color}`}>{c.value}</p>
            </motion.div>
          ))}
        </div>
      )}

      {/* Recent Orders & Top Customers */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Recent Orders */}
        <section className="bg-white rounded-2xl shadow-card p-6">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-xl font-semibold text-purple-700">📄 Recent Orders</h3>
            <AnimatedButton
              size="sm"
              onClick={() =>
                exportCSV(
                  recentOrders.map((o) => ({
                    id: o._id,
                    user: o.user.name,
                    email: o.user.email,
                    date: new Date(o.createdAt).toISOString(),
                    total: o.total.toFixed(2),
                  })),
                  [
                    { key: 'id', label: 'Order ID' },
                    { key: 'user', label: 'Customer' },
                    { key: 'email', label: 'Email' },
                    { key: 'date', label: 'Date' },
                    { key: 'total', label: 'Total' },
                  ],
                  `recent-orders_${startDate}_to_${endDate}`
                )
              }
              className="bg-purple-200 text-purple-700 hover:bg-purple-300"
            >
              Export CSV
            </AnimatedButton>
          </div>
          {recentOrders.length ? (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-purple-100 sticky top-0">
                  <tr>
                    <th className="px-4 py-2 text-left text-sm font-medium text-purple-600">
                      #
                    </th>
                    <th className="px-4 py-2 text-left text-sm font-medium text-purple-600">
                      Customer
                    </th>
                    <th className="px-4 py-2 text-left text-sm font-medium text-purple-600">
                      Date
                    </th>
                    <th className="px-4 py-2 text-right text-sm font-medium text-purple-600">
                      Total
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {recentOrders.map((o, i) => (
                    <motion.tr
                      key={o._id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.05 }}
                      className="border-b even:bg-neutral-50 hover:bg-neutral-100"
                    >
                      <td className="px-4 py-2 text-purple-800">{i + 1}</td>
                      <td className="px-4 py-2 text-purple-700">
                        {o.user.name} ({o.user.email})
                      </td>
                      <td className="px-4 py-2 text-purple-600 whitespace-nowrap">
                        {new Date(o.createdAt).toLocaleString()}
                      </td>
                      <td className="px-4 py-2 text-purple-800 text-right">
                        {o.total.toFixed(2)}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-purple-600">No recent orders.</p>
          )}
        </section>

        {/* Top Customers */}
        <section className="bg-white rounded-2xl shadow-card p-6">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-xl font-semibold text-purple-700">🏆 Top Customers</h3>
            <AnimatedButton
              size="sm"
              onClick={() =>
                exportCSV(
                  topCustomers.map((c) => ({
                    name: c.name,
                    totalSpent: c.totalSpent.toFixed(2),
                  })),
                  [
                    { key: 'name', label: 'Customer' },
                    { key: 'totalSpent', label: 'Total Spent' },
                  ],
                  `top-customers_${startDate}_to_${endDate}`
                )
              }
              className="bg-purple-200 text-purple-700 hover:bg-purple-300"
            >
              Export CSV
            </AnimatedButton>
          </div>
          {topCustomers.length ? (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-purple-100 sticky top-0">
                  <tr>
                    <th className="px-4 py-2 text-left text-sm font-medium text-purple-600">
                      #
                    </th>
                    <th className="px-4 py-2 text-left text-sm font-medium text-purple-600">
                      Customer
                    </th>
                    <th className="px-4 py-2 text-right text-sm font-medium text-purple-600">
                      Total Spent
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {topCustomers.map((c, i) => (
                    <motion.tr
                      key={c._id || i}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.05 }}
                      className="border-b even:bg-neutral-50 hover:bg-neutral-100"
                    >
                      <td className="px-4 py-2 text-purple-800">{i + 1}</td>
                      <td className="px-4 py-2 text-purple-700">{c.name}</td>
                      <td className="px-4 py-2 text-purple-800 text-right">
                        {c.totalSpent.toFixed(2)}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-purple-600">No top customers.</p>
          )}
        </section>
      </div>

      {/* Inventory Alerts */}
      <section className="bg-white rounded-2xl shadow-card p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-xl font-semibold text-purple-700">🚨 Low‐Stock Alerts</h3>
          <AnimatedButton
            size="sm"
            onClick={() =>
              exportCSV(
                lowInventory.map((p) => ({
                  name: p.name,
                  inStock: p.countInStock,
                })),
                [
                  { key: 'name', label: 'Product' },
                  { key: 'inStock', label: 'In Stock' },
                ],
                `low-stock_${threshold}`
              )
            }
            className="bg-purple-200 text-purple-700 hover:bg-purple-300"
          >
            Export CSV
          </AnimatedButton>
        </div>
        {lowInventory.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-purple-100 sticky top-0">
                <tr>
                  <th className="px-4 py-2 text-left text-sm font-medium text-purple-600">
                    Product
                  </th>
                  <th className="px-4 py-2 text-right text-sm font-medium text-purple-600">
                    In Stock
                  </th>
                </tr>
              </thead>
              <tbody>
                {lowInventory.map((p, i) => (
                  <motion.tr
                    key={p._id || i}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className="border-b even:bg-neutral-50 hover:bg-neutral-100"
                  >
                    <td className="px-4 py-2 text-purple-700">{p.name}</td>
                    <td className="px-4 py-2 text-right text-red-600 font-semibold">
                      {p.countInStock}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-purple-600">No low‐stock products.</p>
        )}
      </section>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Sales Over Time */}
        <section className="bg-white rounded-2xl shadow-card p-6 chart-container">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-xl font-semibold text-purple-700">📈 Sales Over Time</h3>
            <AnimatedButton
              size="sm"
              onClick={() =>
                exportCSV(
                  salesData.map((d) => ({
                    date: d.date,
                    totalSales: d.totalSales,
                  })),
                  [
                    { key: 'date', label: 'Date' },
                    { key: 'totalSales', label: 'Total Sales' },
                  ],
                  `sales_${startDate}_to_${endDate}`
                )
              }
              className="bg-purple-200 text-purple-700 hover:bg-purple-300"
            >
              Export CSV
            </AnimatedButton>
          </div>
          {salesData.length ? (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart
                data={salesData}
                margin={{ top: 5, right: 30, left: 0, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" tick={{ fill: '#6B21A8' }} />
                <YAxis tick={{ fill: '#6B21A8' }} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="totalSales"
                  stroke={COLORS[0]}
                  strokeWidth={2}
                  dot={{ r: 3 }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-purple-600">No sales data.</p>
          )}
        </section>

        {/* Top Products */}
        <section className="bg-white rounded-2xl shadow-card p-6 chart-container">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-xl font-semibold text-purple-700">
              🏆 Top 5 Products
            </h3>
            <AnimatedButton
              size="sm"
              onClick={() =>
                exportCSV(
                  topProducts.map((p) => ({
                    name: p.name,
                    totalRevenue: p.totalRevenue.toFixed(2),
                  })),
                  [
                    { key: 'name', label: 'Product' },
                    { key: 'totalRevenue', label: 'Revenue' },
                  ],
                  `top-products_${startDate}_to_${endDate}`
                )
              }
              className="bg-purple-200 text-purple-700 hover:bg-purple-300"
            >
              Export CSV
            </AnimatedButton>
          </div>
          {topProducts.length ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={topProducts.map((p) => ({
                  name: p.name,
                  revenue: p.totalRevenue,
                }))}
                margin={{ top: 5, right: 30, left: 0, bottom: 80 }}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="name"
                  angle={-45}
                  textAnchor="end"
                  interval={0}
                  height={60}
                  tick={{ fill: '#6B21A8' }}
                />
                <YAxis tick={{ fill: '#6B21A8' }} />
                <Tooltip />
                <Bar dataKey="revenue" fill={COLORS[1]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-purple-600">No top products.</p>
          )}
        </section>

        {/* Category Sales */}
        <section className="lg:col-span-2 bg-white rounded-2xl shadow-card p-6 chart-container">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-xl font-semibold text-purple-700">
              📊 Revenue by Category
            </h3>
            <AnimatedButton
              size="sm"
              onClick={() =>
                exportCSV(
                  categorySales.map((c) => ({
                    category: c._id,
                    totalRevenue: c.totalRevenue.toFixed(2),
                  })),
                  [
                    { key: 'category', label: 'Category' },
                    { key: 'totalRevenue', label: 'Revenue' },
                  ],
                  `category-sales`
                )
              }
              className="bg-purple-200 text-purple-700 hover:bg-purple-300"
            >
              Export CSV
            </AnimatedButton>
          </div>
          {categorySales.length ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={categorySales}
                  dataKey="totalRevenue"
                  nameKey="_id"
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  fill={COLORS[2]}
                  label={(entry) => entry._id}
                >
                  {categorySales.map((_, idx) => (
                    <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-purple-600">No category data.</p>
          )}
        </section>
      </div>
    </div>
  )
}
