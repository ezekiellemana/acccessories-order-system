// src/pages/admin/AdminImport.jsx
import React, { useState } from 'react';
import api from '../../services/api';
import { toast } from 'react-toastify';
import AnimatedButton from '../../components/AnimatedButton';

export default function AdminImport() {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleImport = async () => {
    if (!file) {
      toast.error('Please select a CSV file first.');
      return;
    }
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const { data } = await api.post(
        '/api/admin/tools/import-products',
        formData,
        { headers: { 'Content-Type': 'multipart/form-data' } }
      );
      toast.success(`${data.insertedCount} products imported successfully!`);
      setFile(null);
      document.getElementById('import-input').value = '';
    } catch (err) {
      console.error(err);
      toast.error(err.response?.data?.error || 'Import failed.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6">
      <h3 className="text-xl font-medium text-gray-800">Product Import</h3>
      <p className="text-gray-600">
        Upload a CSV file with product data. The backend will parse and insert them in bulk.
      </p>
      <div className="flex items-center space-x-4">
        <input
          type="file"
          id="import-input"
          accept=".csv"
          onChange={handleFileChange}
          className="block w-full text-sm text-gray-700 border border-gray-300 rounded-xl cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary"
        />
        <AnimatedButton
          onClick={handleImport}
          className="px-6"
          disabled={uploading}
        >
          {uploading ? 'Importing…' : 'Import Products'}
        </AnimatedButton>
      </div>
    </div>
  );
}
