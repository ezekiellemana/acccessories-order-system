import React from 'react';
import { Instagram, Facebook, Twitter } from 'lucide-react';
import { motion } from 'framer-motion';

export default function Footer() {
  return (
    <motion.footer
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="bg-gradient-to-r from-primary-800 to-primary-700 text-neutral-100"
    >
      <div className="max-w-7xl mx-auto px-4 py-6 flex flex-col md:flex-row items-center justify-between text-sm md:text-base">
        {/* Address */}
        <div className="space-y-1">
          <p className="font-extrabold">aStore Headquarters</p>
          <p>41218 Tanzannial Telecommunication Cooperation, Dar es Salaam</p>
          <p className="text-xs">support@astore.co.tz | +255 75 277 2587</p>
        </div>

        {/* Quote */}
        <motion.p
          initial={{ scale: 0.9 }}
          animate={{ scale: 1 }}
          transition={{ delay: 0.2, duration: 0.5 }}
          className="italic font-semibold text-center mt-4 md:mt-0 text-neutral-200"
        >
          “Your satisfaction is our inspiration.”
        </motion.p>

        {/* Social Icons */}
        <div className="flex space-x-6 mt-4 md:mt-0">
          <motion.a
            href="https://www.instagram.com/astore.__/"
            target="_blank"
            rel="noopener noreferrer"
            whileHover={{ scale: 1.2, color: '#F77737' }}
            className="text-neutral-100 transition-colors"
          >
            <Instagram size={24} />
          </motion.a>
          <motion.a
            href="https://facebook.com/astore"
            target="_blank"
            rel="noopener noreferrer"
            whileHover={{ scale: 1.2, color: '#4267B2' }}
            className="text-neutral-100 transition-colors"
          >
            <Facebook size={24} />
          </motion.a>
          <motion.a
            href="https://twitter.com/astore"
            target="_blank"
            rel="noopener noreferrer"
            whileHover={{ scale: 1.2, color: '#1DA1F2' }}
            className="text-neutral-100 transition-colors"
          >
            <Twitter size={24} />
          </motion.a>
        </div>
      </div>

      <div className="border-t border-primary-600 bg-primary-900 text-center text-xs py-3 font-semibold">
        &copy; {new Date().getFullYear()} aStore. All rights reserved.
      </div>
    </motion.footer>
  );
}
