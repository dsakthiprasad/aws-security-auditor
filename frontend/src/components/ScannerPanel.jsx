import React, { useState } from 'react';
import api from '../services/api';

const ScannerPanel = ({ onScanSuccess }) => {
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    setScanId(null);
    try {
      const response = await api.post('/scan', {
        aws_account_id: "local-dev-account",
      });
      const id = response.data.scan_id;
      setScanId(id);
      if (onScanSuccess) {
        onScanSuccess(id);
      }
    } catch (err) {
      let message = "Unknown error";

      if (Array.isArray(err.response?.data?.detail)) {
        message = err.response.data.detail
          .map((e) => e.msg)
          .join(", ");
      } else {
        message =
          err.response?.data?.detail ||
          err.message ||
          "An unknown error occurred";
      }

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold text-gray-800 mb-4">
        Run Security Audit
      </h3>
      <div className="space-y-4">
        <button
          onClick={handleScan}
          disabled={loading}
          className="w-full py-4 px-6 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-3"
        >
          {loading ? (
            <>
              <svg className="animate-spin h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"></path>
              </svg>
              <span>Running audit...</span>
            </>
          ) : (
            'Run AWS Security Audit'
          )}
        </button>

        {scanId && (
          <div className="bg-green-50 border-l-4 border-green-500 p-4">
            <p className="text-sm text-green-800">
              Scan completed. Scan ID: <span className="font-mono">{scanId}</span>
            </p>
          </div>
        )}

        {error && (
          <div className="bg-red-50 border-l-4 border-red-500 p-4">
            <p className="text-sm text-red-800">
              Error: {error}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScannerPanel;