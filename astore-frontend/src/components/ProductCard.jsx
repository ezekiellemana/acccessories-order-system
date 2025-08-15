// src/components/ProductCard.jsx
import React from 'react';
import { Link } from 'react-router-dom';
import { FaStar } from 'react-icons/fa';

export default function ProductCard({ product }) {
  const hasDiscount = product.discount > 0;
  const discountedPrice = hasDiscount
    ? Math.round(product.price * (1 - product.discount / 100) * 100) / 100
    : product.price;

  const formatPrice = (price) =>
    `Tsh.${price.toLocaleString('en-TZ', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })}/=`;

  return (
    <Link to={`/products/${product._id}`} className="group block">
      <div className="relative flex flex-col bg-white rounded-2xl shadow hover:shadow-lg overflow-hidden transition">
        {/* IMAGE + BADGES */}
        <div className="relative">
          {hasDiscount && (
            <span className="absolute top-2 left-2 bg-accent-600 text-white text-xs font-medium px-2 py-1 rounded-full z-10">
              {product.discount}% OFF
            </span>
          )}
          {product.isFeatured && (
            <FaStar className="absolute top-2 right-2 text-yellow-500 w-6 h-6" />
          )}
          {product.images?.[0] ? (
            <img
              src={product.images[0]}
              alt={product.name}
              className="w-full h-48 object-cover transition-transform duration-200 group-hover:scale-105"
            />
          ) : (
            <div className="w-full h-48 bg-neutral-100 flex items-center justify-center">
              <span className="text-neutral-400">No Image</span>
            </div>
          )}
          {product.stock === 0 && (
            <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
              <span className="text-white font-semibold">Out of Stock</span>
            </div>
          )}
        </div>

        {/* CONTENT */}
        <div className="p-4 flex flex-col flex-grow space-y-2">
          {/* NAME */}
          <h3 className="text-base font-semibold text-neutral-800 line-clamp-2">
            {product.name}
          </h3>

          {/* CATEGORY + RATING */}
          <div className="flex flex-wrap items-center text-xs space-x-2">
            {product.category?.name && (
              <span className="px-2 py-0.5 bg-neutral-100 rounded-full">
                {product.category.name}
              </span>
            )}
            <div className="flex items-center text-yellow-500">
              <FaStar className="w-3 h-3" />
              <span className="ml-1 text-neutral-700">
                {(product.avgRating ?? 0).toFixed(1)}
              </span>
              <span className="ml-1 text-neutral-500">
                ({product.totalReviews ?? 0})
              </span>
            </div>
          </div>

          {/* PRICE */}
          <div className="mt-auto space-y-1">
            <div className="flex flex-wrap items-baseline space-x-2">
              {hasDiscount && (
                <span className="text-sm text-neutral-500 line-through whitespace-nowrap">
                  {formatPrice(product.price)}
                </span>
              )}
              <span className="text-lg font-bold text-accent-600 whitespace-nowrap">
                {formatPrice(discountedPrice)}
              </span>
            </div>

            {/* STOCK BADGE */}
            <span
              className={`inline-block text-xs font-medium rounded-full px-2 py-0.5 ${
                product.stock > 0
                  ? 'bg-green-50 text-green-700'
                  : 'bg-red-50 text-red-700'
              }`}
            >
              {product.stock > 0
                ? `In Stock (${product.stock})`
                : 'Out of Stock'}
            </span>
          </div>
        </div>
      </div>
    </Link>
  );
}
