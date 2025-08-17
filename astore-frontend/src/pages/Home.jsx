// src/pages/Home.jsx
import React, { useEffect, useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { motion, AnimatePresence } from 'framer-motion';
import { FaChevronLeft, FaChevronRight } from 'react-icons/fa';
import AnimatedButton from '../components/AnimatedButton';
import ProductCard from '../components/ProductCard';

// Helper to format prices like "Tsh.2,250,000.00/="
const formatPrice = (price) =>
  `Tsh.${price.toLocaleString('en-TZ', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}/=`;

// Skeleton loader
function ProductCardSkeleton() {
  return (
    <div className="bg-white rounded-2xl shadow-lg p-4 animate-pulse flex flex-col h-full">
      <div className="w-full h-48 bg-neutral-200 rounded-lg" />
      <div className="h-5 bg-neutral-200 rounded mt-4 w-2/3" />
      <div className="h-4 bg-neutral-100 rounded mt-2 w-1/3" />
      <div className="h-4 bg-neutral-100 rounded mt-2 w-1/2" />
      <div className="mt-auto pt-4 h-6 bg-neutral-100 rounded w-1/3" />
    </div>
  );
}

export default function Home() {
  const [featured, setFeatured] = useState([]);
  const [offers, setOffers] = useState([]);
  const [loadingFeatured, setLoadingFeatured] = useState(true);
  const [loadingOffers, setLoadingOffers] = useState(true);

  const carouselRef = useRef(null);
  const offersRef = useRef([]);
  const [isPaused, setIsPaused] = useState(false);

  // Fetch featured & offers
  useEffect(() => {
    api
      .get('/api/products', { params: { sort: 'createdAt_desc', limit: 4 } })
      .then(r => setFeatured(r.data.products || []))
      .catch(() => setFeatured([]))
      .finally(() => setLoadingFeatured(false));

    api
      .get('/api/products', { params: { discounted: true, limit: 8 } })
      .then(r => {
        const arr = r.data.products || [];
        // shuffle for randomness
        for (let i = arr.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        offersRef.current = arr;
        setOffers(arr.slice(0, 4));
      })
      .catch(() => setOffers([]))
      .finally(() => setLoadingOffers(false));
  }, []);

  // Auto‐advance carousel every 3s
  useEffect(() => {
    if (!carouselRef.current || offersRef.current.length <= 4) return;
    const iv = setInterval(() => {
      if (isPaused) return;
      const el = carouselRef.current;
      const nextScroll = el.scrollLeft + el.offsetWidth;
      if (nextScroll + 1 >= el.scrollWidth) {
        el.scrollTo({ left: 0, behavior: 'smooth' });
      } else {
        el.scrollBy({ left: el.offsetWidth, behavior: 'smooth' });
      }
    }, 3000);
    return () => clearInterval(iv);
  }, [isPaused]);

  // Handlers for manual nav
  const scrollPrev = () => {
    const el = carouselRef.current;
    if (!el) return;
    const prev = el.scrollLeft - el.offsetWidth;
    el.scrollTo({ left: prev < 0 ? el.scrollWidth : prev, behavior: 'smooth' });
  };
  const scrollNext = () => {
    const el = carouselRef.current;
    if (!el) return;
    const next = el.scrollLeft + el.offsetWidth;
    el.scrollTo({ left: next >= el.scrollWidth ? 0 : next, behavior: 'smooth' });
  };

  return (
    <div className="pt-20 space-y-20">
      {/* Hero */}
      <section className="relative bg-gradient-to-r from-primary-100 to-primary-50 py-20 rounded-2xl shadow-card overflow-hidden">
        <div className="absolute inset-0 opacity-10 bg-[url('/hero-bg.svg')] bg-center bg-no-repeat" />
        <div className="relative max-w-3xl mx-auto text-center px-6 space-y-6">
          <h1 className="text-5xl sm:text-6xl font-extrabold text-primary-800">
            Welcome to aStore
          </h1>
          <p className="text-xl sm:text-2xl text-primary-600">
            Discover our most popular products with exclusive deals and free shipping.
          </p>
          <Link to="/products">
            <motion.div whileHover={{ scale: 1.05 }} transition={{ duration: 0.3 }}>
              <AnimatedButton className="px-10 py-3 text-lg bg-gradient-to-r from-accent-500 to-accent-700 text-white font-semibold rounded-2xl shadow-lg hover:shadow-xl transition">
                Browse Products
              </AnimatedButton>
            </motion.div>
          </Link>
        </div>
      </section>

      {/* Featured Products */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
        <h2 className="text-3xl font-semibold text-neutral-800">Featured Products</h2>
        {loadingFeatured ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
            {[...Array(4)].map((_, i) => <ProductCardSkeleton key={i} />)}
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
            {featured.length
              ? featured.map(p => <ProductCard key={p._id} product={p} />)
              : <p className="col-span-4 text-center text-neutral-500">No featured products.</p>}
          </div>
        )}
      </section>

      {/* Offers & Discounts Carousel */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
        <h2 className="text-3xl font-semibold text-neutral-800">Offers & Discounts</h2>
        {loadingOffers ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
            {[...Array(4)].map((_, i) => <ProductCardSkeleton key={i} />)}
          </div>
        ) : offers.length ? (
          <div
            className="relative"
            onMouseEnter={() => setIsPaused(true)}
            onMouseLeave={() => setIsPaused(false)}
          >
            {/* Carousel viewport */}
            <div
              className="overflow-x-auto snap-x snap-mandatory scroll-smooth"
              ref={carouselRef}
            >
              <div className="inline-flex gap-6 px-4 sm:px-0">
                {offers.map(p => (
                  <div key={p._id} className="snap-start flex-shrink-0 w-[240px] md:w-auto">
                    <ProductCard product={p} />
                  </div>
                ))}
              </div>
            </div>

            {/* Nav arrows (desktop only) */}
            <button
              onClick={scrollPrev}
              className="hidden md:flex absolute left-2 top-1/2 transform -translate-y-1/2 bg-white p-2 rounded-full shadow hover:bg-neutral-100"
            >
              <FaChevronLeft />
            </button>
            <button
              onClick={scrollNext}
              className="hidden md:flex absolute right-2 top-1/2 transform -translate-y-1/2 bg-white p-2 rounded-full shadow hover:bg-neutral-100"
            >
              <FaChevronRight />
            </button>
          </div>
        ) : (
          <p className="text-center text-neutral-500">No current offers.</p>
        )}
      </section>
    </div>
  );
}
