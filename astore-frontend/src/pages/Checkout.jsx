import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import api from '../services/api';
import { toast } from 'react-toastify';
import AnimatedButton from '../components/AnimatedButton';
import { jsPDF } from 'jspdf';

export default function Checkout() {
  const [cartItems, setCartItems] = useState([]);
  const [loadingCart, setLoadingCart] = useState(true);
  const [placingOrder, setPlacingOrder] = useState(false);
  const [showAnimation, setShowAnimation] = useState(false);
  const [orderPlaced, setOrderPlaced] = useState(false);
  const [showPopup, setShowPopup] = useState(false);
  const [receiptUrl, setReceiptUrl] = useState(null);
  const [orderId, setOrderId] = useState(null);
  const shipping = 2000;

  useEffect(() => {
    const fetchCart = async () => {
      setLoadingCart(true);
      try {
        const { data } = await api.get('/api/cart');
        setCartItems(data.items);
      } catch {
        toast.error('Could not load your cart.');
      } finally {
        setLoadingCart(false);
      }
    };
    fetchCart();
  }, []);

  const subtotal = cartItems.reduce((sum, { product, quantity }) => {
    const price = product.discount
      ? product.price * (1 - product.discount / 100)
      : product.price;
    return sum + price * quantity;
  }, 0);

  const generatePDF = (id) => {
    const doc = new jsPDF({ unit: 'pt', format: 'a6' });
    const w = doc.internal.pageSize.getWidth();
    let y = 20;
    doc.setFillColor('#2255A3').rect(0, 0, w, 60, 'F');
    doc.setFontSize(14).setTextColor('#FFF').setFont('helvetica', 'bold');
    doc.text('eStore Receipt', 20, 28);
    doc.setFontSize(9).setTextColor('#333').setFont('helvetica', 'normal');
    doc.text(`Order ID: ${id}`, 20, (y = 70));
    doc.text(`Date: ${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}`, 20, y + 12);
    y += 40;
    doc.setLineWidth(0.5).setDrawColor('#CCC').line(20, y, w - 20, y);
    y += 20;
    doc.setFontSize(8).setFont('helvetica', 'bold');
    doc.text('Product', 24, y);
    doc.text('Qty', 24 + 120, y);
    doc.text('Total', w - 24, y, { align: 'right' });
    y += 16;
    doc.setFont('helvetica', 'normal');
    cartItems.forEach(({ product, quantity }, idx) => {
      const price = product.discount ? product.price * (1 - product.discount / 100) : product.price;
      const total = (price * quantity).toLocaleString('en-US', { minimumFractionDigits: 2 });
      if (idx % 2 === 1) doc.setFillColor('#F9F9F9').rect(20, y - 12, w - 40, 16, 'F');
      doc.text(product.name, 24, y);
      doc.text(String(quantity), 24 + 120, y);
      doc.text(total, w - 24, y, { align: 'right' });
      y += 16;
      if (y + 40 > doc.internal.pageSize.getHeight()) {
        doc.addPage('a6');
        y = 20;
      }
    });
    y += 20;
    doc.line(20, y, w - 20, y);
    y += 20;
    const totalAll = subtotal + shipping;
    doc.setFont('helvetica', 'bold').setFontSize(10);
    doc.text(`Subtotal: Tsh.${subtotal.toLocaleString('en-US', { minimumFractionDigits: 2 })}`, 20, y);
    doc.text(`Shipping: Tsh.${shipping.toLocaleString()}`, 20, y + 14);
    doc.setFontSize(12).text(`TOTAL: Tsh.${totalAll.toLocaleString()}`, 20, y + 32);
    doc.setFontSize(8).setFont('helvetica', 'italic').setTextColor('#666');
    doc.text('Thank you for shopping at eStore!', 20, y + 50);
    return URL.createObjectURL(doc.output('blob'));
  };

  const buildWhatsAppMessage = (orderId) => {
    const number = import.meta.env.VITE_WHATSAPP_NUMBER;

    const lineItems = cartItems.map(({ product, quantity }) => {
      const price = product.discount
        ? product.price * (1 - product.discount / 100)
        : product.price;
      const itemTotal = price * quantity;
      return `• ${product.name} x${quantity} = Tsh.${itemTotal.toLocaleString('en-US', { minimumFractionDigits: 0 })}`;
    });

    const total = subtotal + shipping;

    const message = `Hello! I just placed an order (#${orderId}) from eStore.\n\n${lineItems.join(
      '\n'
    )}\n\nSubtotal: Tsh.${subtotal.toLocaleString('en-US')}\nShipping: Tsh.${shipping.toLocaleString('en-US')}\n\nTOTAL: Tsh.${total.toLocaleString('en-US')}\n\nThank you!`;

    return `https://wa.me/${number}?text=${encodeURIComponent(message)}`;
  };


  const placeOrder = async () => {
    if (!cartItems.length) return toast.error('Cart is empty');
    setPlacingOrder(true);
    try {
      const items = cartItems.map(({ product, quantity }) => ({
        productId: product._id,
        quantity,
        price: product.discount ? product.price * (1 - product.discount / 100) : product.price,
      }));
      const { data } = await api.post('/api/orders', { items });
      setOrderId(data._id);
      setReceiptUrl(generatePDF(data._id));
      setShowAnimation(true);
      setShowPopup(true);
      setOrderPlaced(true);
      setCartItems([]);
      toast.success('Order placed! Redirecting to WhatsApp...');
      setTimeout(() => setShowPopup(false), 2000);
      setTimeout(() => setShowAnimation(false), 2500);
      setTimeout(() => {
        window.open(buildWhatsAppMessage(data._id), '_blank');
      }, 1500);
    } catch (err) {
      console.error(err);
      toast.error('Failed to place order');
    } finally {
      setPlacingOrder(false);
    }
  };

  const downloadReceipt = () => {
    if (!receiptUrl || !orderId) return;
    const a = document.createElement('a');
    a.href = receiptUrl;
    a.download = `receipt_${orderId}.pdf`;
    a.click();
    URL.revokeObjectURL(receiptUrl);
  };

  if (loadingCart)
    return <div className="flex justify-center items-center h-64"><p className="text-gray-500">Loading…</p></div>;

  if (!cartItems.length)
    return <div className="text-center py-16"><h2 className="text-2xl font-bold">Cart is empty</h2></div>;

  const particles = Array.from({ length: 20 }).map((_, i) => ({
    id: i,
    x: Math.random() * window.innerWidth,
    delay: Math.random() * 0.5,
    rotate: Math.random() * 360,
  }));

  return (
    <div className="relative max-w-md mx-auto py-8 space-y-6">
      <h2 className="text-3xl font-bold text-center">Checkout</h2>
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="bg-white rounded-xl shadow-lg p-6 space-y-4">
        <p className="text-gray-600">Subtotal: <span className="font-semibold">Tsh.{subtotal.toLocaleString('en-US', { minimumFractionDigits: 2 })}</span></p>
        <p className="text-gray-600">Shipping: <span className="font-semibold">Tsh.{shipping.toLocaleString()}</span></p>
        <p className="text-xl font-bold">Total: <span className="text-primary-600">Tsh.{(subtotal + shipping).toLocaleString()}</span></p>
        <AnimatedButton onClick={placeOrder} className="w-full py-3" disabled={placingOrder || orderPlaced}>
          {placingOrder ? 'Placing…' : orderPlaced ? 'Placed' : 'Place Order'}
        </AnimatedButton>
      </motion.div>

      {orderPlaced && (
        <AnimatedButton onClick={downloadReceipt} className="w-full py-3 bg-green-600 hover:bg-green-700">
          Download Receipt
        </AnimatedButton>
      )}

      <AnimatePresence>
        {showAnimation && (
          <>
            {particles.map(({ id, x, delay, rotate }) => (
              <motion.div key={`balloon_${id}`} initial={{ y: window.innerHeight + 50, x }} animate={{ y: -50, x: x + (Math.random() * 100 - 50), rotate: rotate + 360 }} transition={{ duration: 2 + Math.random(), delay }} style={{ left: x }} className="absolute text-5xl">🎈</motion.div>
            ))}
            {particles.map(({ id, x, delay, rotate }) => (
              <motion.div key={`confetti_${id}`} initial={{ y: -20, x, opacity: 0 }} animate={{ y: window.innerHeight + 20, opacity: 1, rotate }} transition={{ duration: 3, delay }} style={{ left: x }} className="absolute text-lg">🎉</motion.div>
            ))}
          </>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showPopup && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
            <motion.div initial={{ scale: 0.7, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.7, opacity: 0 }} transition={{ type: 'spring', stiffness: 260, damping: 20 }} className="bg-gradient-to-r from-blue-400 to-indigo-600 text-white rounded-3xl p-8 shadow-2xl text-center max-w-sm mx-4">
              <motion.div initial={{ rotate: 0 }} animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: 'linear' }} className="text-6xl mb-4">🎊</motion.div>
              <h3 className="text-3xl font-bold mb-2">Congratulations!</h3>
              <p className="text-lg opacity-80">Your order #{orderId} is confirmed</p>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
