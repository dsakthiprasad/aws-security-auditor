import React, { useState, useEffect, useRef } from "react";
import ScannerPanel from "../components/ScannerPanel";
import ScoreCard from "../components/ScoreCard";
import FindingsTable from "../components/FindingsTable";
import RemediationPanel from "../components/RemediationPanel";
import api from "../services/api";
import html2pdf from "html2pdf.js";

const DashboardPage = () => {
  const [scanId, setScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isGeneratingPDF, setIsGeneratingPDF] = useState(false);
  const dashboardRef = useRef(null);

  const handleScanSuccess = (scan) => {
    setScanId(scan.scan_id);
    setScanData(scan);
  };

  const exportToPDF = async () => {
    setIsGeneratingPDF(true);
    // Wait for DOM to update after state change
    await new Promise(resolve => setTimeout(resolve, 0));
    try {
      const element = dashboardRef.current;
      if (!element) {
        console.error('No dashboard element');
        return;
      }
      // Use html2pdf.js to generate PDF
      await html2pdf()
        .set({
          margin: 0.5,
          filename: 'aws-security-report.pdf',
          image: { type: 'jpeg', quality: 0.98 },
          html2canvas: { scale: 2 },
          jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
        })
        .from(element)
        .save();
    } catch (err) {
      console.error('PDF generation failed:', err);
      alert('Failed to generate PDF. Please try again.');
    } finally {
      setIsGeneratingPDF(false);
    }
  };
/*
  useEffect(() => {
    if (!scanId) return;

    const fetchResults = async () => {
      try {
        setLoading(true);

        const response = await api.get(`/history/scans/${scanId}`);

        setScanData(response.data);
      } catch (err) {
        console.error("Failed to fetch scan:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchResults();
  }, [scanId]);
*/
  return (
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold text-gray-900">
          AWS Security Audit Dashboard
        </h2>

        <p className="text-gray-500 mt-2">
          Run security scans and review findings with compliance scoring.
        </p>

        {/* Export PDF Button - outside the exported container */}
        <button
          onClick={exportToPDF}
          disabled={!scanId || isGeneratingPDF}
          className={`mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition
            ${isGeneratingPDF ? 'bg-gray-400 cursor-not-allowed' : ''}`}
        >
          {isGeneratingPDF ? 'Generating...' : 'Export Security Report (PDF)'}
        </button>
      </div>

      {/* Wrap the dashboard content in a ref for PDF export */}
      <div ref={dashboardRef}>
        {/* Report header - only rendered during PDF generation */}
        {isGeneratingPDF && (
          <div className="mb-6">
            <h1 className="text-2xl font-bold text-center mb-2">
              AWS Security Audit Report
            </h1>
            <p className="text-center text-gray-500">
              {new Date().toLocaleString()}
            </p>
            <hr className="my-4 border-t-2 border-gray-300" />
          </div>
        )}

        {/* ScannerPanel only visible on dashboard, not in PDF */}
        {!isGeneratingPDF && (
          <ScannerPanel onScanSuccess={handleScanSuccess} />
        )}

        {loading && (
          <div className="bg-white rounded-lg shadow p-6 text-center">
            Loading scan results...
          </div>
        )}

        {!loading && scanData && (
          <>
            <ScoreCard scanData={scanData} />

            <FindingsTable
              findings={scanData.findings || []}
            />

            <RemediationPanel scanId={scanId} />
          </>
        )}
      </div>
    </div>
  );
};

export default DashboardPage;