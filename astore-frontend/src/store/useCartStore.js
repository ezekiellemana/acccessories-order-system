// src/store/useCartStore.js

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

const useCartStore = create(
  persist(
    (set, get) => ({
      items: [],

      // total number of items in cart (for badge, etc.)
      getTotalItems: () =>
        get().items.reduce((sum, i) => sum + (i.qty ?? 0), 0),

      // subtotal using discounted prices
      getSubtotal: () =>
        get().items.reduce((sum, i) => {
          const price = i.price ?? 0;
          const discount = i.discount ?? 0;
          const discountedPrice = discount > 0
            ? price * (1 - discount / 100)
            : price;
          return sum + discountedPrice * (i.qty ?? 0);
        }, 0),

      // add product (with optional variant) to cart
      addToCart: (product, qty = 1, variant = null) => {
        set((state) => {
          const key = variant ? `${product._id}_${variant}` : product._id;
          const exists = state.items.find((i) => i.key === key);

          if (exists) {
            return {
              items: state.items.map((i) =>
                i.key === key ? { ...i, qty: i.qty + qty } : i
              ),
            };
          } else {
            return {
              items: [
                ...state.items,
                {
                  key,                             // unique key
                  productId: product._id,          // backend ID
                  name: product.name,
                  image: product.images?.[0] || '',
                  price: product.price,            // original price
                  discount: product.discount ?? 0, // discount %
                  stock: product.stock,            // countInStock
                  qty,
                  variant,                         // e.g. "M/Black"
                },
              ],
            };
          }
        });
      },

      // update quantity for a given cart item
      updateQty: (key, qty) =>
        set((state) => ({
          items: state.items.map((i) =>
            i.key === key ? { ...i, qty } : i
          ),
        })),

      // remove item by key
      removeFromCart: (key) =>
        set((state) => ({
          items: state.items.filter((i) => i.key !== key),
        })),

      // clear the entire cart
      clearCart: () => set({ items: [] }),
    }),
    {
      name: 'astore-cart-storage', // localStorage key
    }
  )
);

export default useCartStore;
