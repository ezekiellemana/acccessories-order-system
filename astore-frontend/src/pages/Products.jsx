// src/pages/Products.jsx

import React, { useEffect, useState, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../services/api';
import ProductCard from '../components/ProductCard';
import { motion, AnimatePresence } from 'framer-motion';
import { FaSearch, FaFilter } from 'react-icons/fa';

// same skeleton you had
function ProductGridSkeleton({ count = 12 }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="bg-white rounded-2xl shadow-lg p-4 animate-pulse flex flex-col h-full"
        >
          <div className="w-full h-48 bg-neutral-200 rounded-lg" />
          <div className="h-5 bg-neutral-200 rounded mt-4 w-2/3" />
          <div className="h-4 bg-neutral-100 rounded mt-2 w-1/3" />
          <div className="h-4 bg-neutral-100 rounded mt-2 w-1/2" />
          <div className="mt-auto pt-4 h-6 bg-neutral-100 rounded w-1/3" />
        </div>
      ))}
    </div>
  );
}

export default function Products() {
  const [searchParams, setSearchParams] = useSearchParams();
  const categoryId = searchParams.get('category') || '';
  const [searchInput, setSearchInput] = useState(searchParams.get('search') || '');

  const [products, setProducts] = useState([]);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  const [categoryOptions, setCategoryOptions] = useState([]);
  const [showFilters, setShowFilters] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState(categoryId);

  // keep URL → selectedCategory in sync
  useEffect(() => {
    setSelectedCategory(categoryId);
    setPage(1);
  }, [categoryId]);

  // load category list once
  const didFetchCats = useRef(false);
  useEffect(() => {
    if (didFetchCats.current) return;
    didFetchCats.current = true;
    (async () => {
      try {
        const { data } = await api.get('/api/categories');
        setCategoryOptions(Array.isArray(data) ? data : []);
      } catch {
        setCategoryOptions([]);
      }
    })();
  }, []);

  // apply filters back into URL
  const applyFilters = () => {
    setPage(1);
    const params = {};
    if (searchInput.trim()) params.search = searchInput.trim();
    if (selectedCategory) params.category = selectedCategory;
    setSearchParams(params);
    setShowFilters(false);
  };

  // fetch products whenever page, URL-params or selectedCategory changes
  useEffect(() => {
    const fetchProds = async () => {
      setLoading(true);
      try {
        const params = { page, limit: 12, sort: 'newest' };
        if (searchParams.get('search')) params.search = searchParams.get('search');
        if (selectedCategory) params.category = selectedCategory;

        const { data } = await api.get('/api/products', { params });
        setProducts(data.products || []);
        setPages(data.totalPages || 1);
      } catch (err) {
        console.error('Failed to fetch products', err);
        setProducts([]);
        setPages(1);
      } finally {
        setLoading(false);
      }
    };
    fetchProds();
  }, [page, searchParams, selectedCategory]);

  const handleSearchKeyPress = (e) => {
    if (e.key === 'Enter') applyFilters();
  };

  // find friendly name for header
  const activeCatName =
    categoryOptions.find((c) => c._id === selectedCategory)?.name || 'All';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
        <h2 className="text-2xl font-bold text-neutral-800">
          {activeCatName} Products
        </h2>

        <div className="flex items-center space-x-2 w-full lg:w-auto">
          <div className="relative w-full lg:w-72">
            <FaSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-neutral-400" />
            <input
              type="text"
              placeholder="Search products…"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={handleSearchKeyPress}
              className="w-full pl-10 pr-4 py-2 border border-neutral-300 rounded-2xl bg-neutral-50 shadow-inner focus:outline-none focus:ring-2 focus:ring-primary-300"
            />
          </div>

          <button
            onClick={() => setShowFilters((v) => !v)}
            className="flex items-center px-4 py-2 bg-primary-600 text-white rounded-2xl hover:bg-primary-700 transition-colors"
          >
            <FaFilter className="mr-2" />
            {showFilters ? 'Hide Filters' : 'Show Filters'}
          </button>
        </div>
      </div>

      {/* Filter Panel */}
      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden bg-white rounded-2xl shadow-card p-6"
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label htmlFor="category" className="block text-sm font-medium text-neutral-700">
                  Category
                </label>
                <select
                  id="category"
                  value={selectedCategory}
                  onChange={(e) => {
                    setSelectedCategory(e.target.value);
                    setPage(1);
                  }}
                  className="mt-1 block w-full border border-neutral-300 rounded-2xl px-3 py-2 bg-neutral-50 shadow-inner focus:outline-none focus:ring-2 focus:ring-primary-300"
                >
                  <option value="">All Categories</option>
                  {categoryOptions.map((cat) => (
                    <option key={cat._id} value={cat._id}>
                      {cat.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex items-center space-x-4 mt-6">
              <button
                onClick={applyFilters}
                className="ml-auto px-6 py-2 bg-primary-600 text-white rounded-2xl hover:bg-primary-700 transition-colors"
              >
                Apply
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Product Grid */}
      {loading ? (
        <ProductGridSkeleton />
      ) : products.length === 0 ? (
        <p className="text-center text-neutral-500">No products found.</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
          {products.map((product, idx) => (
            <motion.div
              key={product._id}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: idx * 0.05, duration: 0.3 }}
            >
              <ProductCard product={product} />
            </motion.div>
          ))}
        </div>
      )}

      {/* Pagination */}
      <div className="flex items-center justify-center space-x-4 mt-6">
        <button
          onClick={() => setPage((p) => Math.max(p - 1, 1))}
          disabled={page === 1}
          className="px-4 py-2 bg-neutral-200 text-neutral-700 rounded-2xl hover:bg-neutral-300 disabled:opacity-50"
        >
          Previous
        </button>
        <span className="text-neutral-600">
          Page {page} of {pages}
        </span>
        <button
          onClick={() => setPage((p) => Math.min(p + 1, pages))}
          disabled={page === pages}
          className="px-4 py-2 bg-neutral-200 text-neutral-700 rounded-2xl hover:bg-neutral-300 disabled:opacity-50"
        >
          Next
        </button>
      </div>
    </div>
  );
}
