import React from 'react';
import { Outlet } from 'react-router-dom';
import StatusBadge from '../components/StatusBadge';

const DashboardLayout = ({ children }) => {
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Top Navigation Bar */}
      <nav className="bg-white shadow-md px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          {/* Shield Icon - using a simple div for now, can be replaced with actual icon */}
          <div className="w-8 h-8 bg-green-600 rounded flex items-center justify-center text-white">
            shield
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-800">AWS Security Auditor</h1>
            <p className="text-sm text-gray-500">Intelligent Terraform Remediation</p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <StatusBadge variant="success" size="sm">
            Backend Connected
          </StatusBadge>
        </div>
      </nav>

      {/* Page Content */}
      <main className="px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
};

export default DashboardLayout;