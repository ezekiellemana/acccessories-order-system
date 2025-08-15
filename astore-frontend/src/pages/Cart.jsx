// src/pages/Cart.jsx

import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import api from '../services/api';
import { motion } from 'framer-motion';
import { toast } from 'react-toastify';
import AnimatedButton from '../components/AnimatedButton';

export default function Cart() {
  const [cart, setCart] = useState({ items: [] });   // <<< default to empty items
  const [loading, setLoading] = useState(true);
  const [updatingItemId, setUpdatingItemId] = useState(null);
  const navigate = useNavigate();

  // Fetch cart
  const fetchCart = async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/api/cart');
      setCart(data ?? { items: [] });
    } catch (err) {
      console.error('Failed to load cart:', err);
      toast.error('Could not load cart.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCart();
  }, []);

  // Calculate subtotal (guard discount & price)
  const subtotal = cart.items.reduce((sum, item) => {
    const price = item.product?.price ?? 0;
    const discountPct = item.product?.discount ?? 0;
    const discountedPrice = discountPct > 0
      ? price * (1 - discountPct / 100)
      : price;
    return sum + discountedPrice * (item.quantity ?? 0);
  }, 0);

  // Update quantity
  const handleQtyChange = async (productId, newQty) => {
    setUpdatingItemId(productId);
    try {
      await api.delete(`/api/cart/${productId}`);
      await api.post('/api/cart', { productId, quantity: newQty });
      toast.success('Quantity updated.');
      await fetchCart();
    } catch (err) {
      console.error('Failed to update quantity:', err);
      toast.error('Could not update quantity.');
    } finally {
      setUpdatingItemId(null);
    }
  };

  // Remove item
  const handleRemove = async (productId) => {
    setUpdatingItemId(productId);
    try {
      await api.delete(`/api/cart/${productId}`);
      toast.success('Item removed from cart.');
      await fetchCart();
    } catch (err) {
      console.error('Failed to remove item:', err);
      toast.error('Could not remove item.');
    } finally {
      setUpdatingItemId(null);
    }
  };

  // Checkout
  const handleCheckout = () => {
    if (cart.items.length === 0) {
      toast.error('Your cart is empty.');
      return;
    }
    navigate('/checkout');
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <p className="text-neutral-500">Loading cart…</p>
      </div>
    );
  }

  if (cart.items.length === 0) {
    return (
      <div className="space-y-8">
        <h2 className="text-2xl font-bold text-neutral-800">Shopping Cart</h2>
        <p className="text-neutral-500">
          Your cart is empty.{' '}
          <Link to="/products" className="text-accent hover:underline">
            Shop Now
          </Link>
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <h2 className="text-2xl font-bold text-neutral-800">Shopping Cart</h2>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        {/* Cart Items List */}
        <div className="md:col-span-2 space-y-4">
          {cart.items.map((item, idx) => {
            const price = item.product?.price ?? 0;
            const discountPct = item.product?.discount ?? 0;
            const discountedPrice = discountPct > 0
              ? price * (1 - discountPct / 100)
              : price;

            return (
              <motion.div
                key={item.product?._id ?? idx}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.05 }}
                className="flex items-center bg-white rounded-2xl shadow-card p-4"
              >
                <img
                  src={item.product?.images?.[0] || '/placeholder.png'}
                  alt={item.product?.name ?? 'Product'}
                  className="w-24 h-24 object-cover rounded-xl"
                />

                <div className="ml-4 flex-1">
                  <Link
                    to={`/products/${item.product?._id}`}
                    className="font-medium text-neutral-800 hover:underline"
                  >
                    {item.product?.name ?? 'Unnamed Product'}
                  </Link>
                  <p className="text-neutral-600">
                    Tsh.{discountedPrice.toFixed(2)}
                    {discountPct > 0 && (
                      <span className="ml-2 text-sm text-neutral-500 line-through">
                        Tsh.{price.toFixed(2)}
                      </span>
                    )}
                  </p>

                  <div className="mt-2 flex items-center space-x-2">
                    <label className="text-neutral-700">Qty:</label>
                    <select
                      value={item.quantity}
                      onChange={(e) =>
                        handleQtyChange(item.product?._id, Number(e.target.value))
                      }
                      disabled={updatingItemId === item.product?._id}
                      className="border border-neutral-300 rounded-2xl px-3 py-2 bg-neutral-50 shadow-inner focus:outline-none focus:ring-2 focus:ring-primary-300"
                    >
                      {[...Array(item.product?.stock ?? 1).keys()].map((x) => (
                        <option key={x + 1} value={x + 1}>
                          {x + 1}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <button
                  onClick={() => handleRemove(item.product?._id)}
                  disabled={updatingItemId === item.product?._id}
                  className="text-red-500 hover:text-red-700 focus:outline-none ml-4"
                >
                  Remove
                </button>
              </motion.div>
            );
          })}
        </div>

        {/* Order Summary */}
        <div className="bg-white rounded-2xl shadow-card p-6 space-y-4">
          <h3 className="text-xl font-medium text-neutral-800">Order Summary</h3>
          <p className="text-neutral-600">
            Subtotal ({cart.items.length} items):{' '}
            <span className="font-bold">Tsh.{subtotal.toFixed(2)}</span>
          </p>
          <AnimatedButton onClick={handleCheckout} className="w-full">
            Proceed to Checkout
          </AnimatedButton>
        </div>
      </div>
    </div>
  );
}
