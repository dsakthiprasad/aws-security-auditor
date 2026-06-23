import React, { useState, useEffect, useRef } from "react";
import api from "../services/api";
import { Bot, AlertTriangle, Download, Info } from 'lucide-react';

const RemediationPanel = ({ scanId }) => {
  const [aiExplanations, setAiExplanations] = useState([]);
  const [terraformBlocks, setTerraformBlocks] = useState([]);
  const [manualGuidance, setManualGuidance] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copiedIndex, setCopiedIndex] = useState(-1);
  const copyTimeoutRef = useRef(null);

  useEffect(() => {
    if (!scanId) {
      // Reset data when scanId is null
      setAiExplanations([]);
      setTerraformBlocks([]);
      setManualGuidance([]);
      setError(null);
      return;
    }

    const fetchRemediation = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await api.get(`/remediate/${scanId}`);
        const remediationData = response.data.remediation || {};

        // Store AI explanations as array of objects (issue_type and explanation)
        setAiExplanations(remediationData.ai_explanations || []);

        // Extract Terraform blocks (array of objects)
        setTerraformBlocks(remediationData.terraform || []);

        // Store manual guidance as array of objects (issue_type, guidance, priority)
        setManualGuidance(remediationData.manual_guidance || []);
      } catch (err) {
        console.error("Failed to fetch remediation:", err);
        setError("Failed to load remediation data.");
      } finally {
        setLoading(false);
      }
    };

    fetchRemediation();
  }, [scanId]);

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) {
        clearTimeout(copyTimeoutRef.current);
      }
    };
  }, []);

  const handleCopy = (index, text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedIndex(index);
      if (copyTimeoutRef.current) {
        clearTimeout(copyTimeoutRef.current);
      }
      copyTimeoutRef.current = setTimeout(() => {
        setCopiedIndex(-1);
      }, 2000);
    });
  };

  const handleDownloadTerraform = () => {
    if (terraformBlocks.length === 0) return;

    // Combine all Terraform blocks with separators
    const combinedContent = terraformBlocks
      .map(
        (block) =>
          `##################################################\n# ${block.filename}\n##################################################\n\n${block.content}`
      )
      .join("\n\n");

    // Create a Blob and trigger download
    const blob = new Blob([combinedContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "aws-remediation.tf";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="bg-white rounded-2xl shadow-xl p-8 mt-8 text-center">
        <h2 className="text-2xl font-bold mb-4">AI Remediation Hub</h2>
        <p className="text-gray-500">Loading remediation data...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white rounded-2xl shadow-xl p-8 mt-8">
        <h2 className="text-2xl font-bold mb-4">AI Remediation Hub</h2>
        <p className="text-red-600">{error}</p>
      </div>
    );
  }

  // If no scanId, show placeholder
  if (!scanId) {
    return (
      <div className="bg-white rounded-2xl shadow-xl p-8 mt-8">
        <h2 className="text-2xl font-bold mb-4">AI Remediation Hub</h2>
        <p className="text-gray-500 text-center">
          Run a scan to view AI-powered remediation guidance.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl shadow-xl p-8 mt-8">
      <h2 className="text-2xl font-bold mb-6">AI Remediation Hub</h2>

      {/* AI Explanations */}
      <div className="mb-8">
        <h3 className="text-xl font-semibold mb-4">AI Explanations</h3>
        {aiExplanations.length === 0 ? (
          <p className="text-gray-500">No AI explanations available.</p>
        ) : (
          <div className="space-y-4">
            {aiExplanations.map((exp, index) => (
              <div key={index} className="bg-blue-50 rounded-lg shadow p-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-start">
                    <Bot className="w-5 h-5 text-blue-500 mr-2" />
                    <h4 className="font-semibold text-lg text-gray-900">
                      {exp.issue_type}
                    </h4>
                  </div>
                  <div>
                    {copiedIndex === index ? (
                      <span className="text-green-600 text-xs">Copied!</span>
                    ) : (
                      <button
                        onClick={() => handleCopy(index, exp.explanation)}
                        className="px-2 py-1 bg-blue-500 text-white text-xs rounded hover:bg-blue-600 transition"
                      >
                        Copy
                      </button>
                    )}
                  </div>
                </div>
                <p className="mt-2 text-gray-700">
                  {exp.explanation}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Terraform Code */}
      <div className="mb-8">
        <h3 className="text-xl font-semibold mb-4 flex items-center justify-between">
          Terraform Remediation
          <button
            onClick={handleDownloadTerraform}
            disabled={terraformBlocks.length === 0}
            className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded
              ${terraformBlocks.length === 0
                ? "bg-gray-200 text-gray-400 cursor-not-allowed"
                : "bg-emerald-600 text-white hover:bg-emerald-700 transition"}`}
          >
            <Download className="w-4 h-4" />
            Download Terraform (.tf)
          </button>
        </h3>
        {terraformBlocks.length === 0 ? (
          <div className="bg-blue-50 rounded-lg shadow p-6 text-center">
            <Info className="w-8 h-8 mx-auto mb-4 text-blue-500" />
            <h3 className="font-semibold text-lg text-gray-900 mb-2">
              No Automatic Terraform Remediation Available
            </h3>
            <p className="text-gray-700 max-w-xl mx-auto">
              The detected findings require manual administrative actions and cannot be safely remediated using Terraform. Review the Manual Guidance section below for recommended steps.
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            {terraformBlocks.map((block, index) => (
              <div key={index} className="border rounded-lg p-4 bg-gray-50">
                <div className="flex justify-between items-start mb-2">
                  <span className="font-mono text-sm">
                    {block.filename || `Terraform Resource ${index + 1}`}
                  </span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(block.content).then(() => {
                        alert("Terraform code copied to clipboard!");
                      });
                    }}
                    className="px-3 py-1 bg-blue-500 text-white text-sm rounded hover:bg-blue-600 transition"
                  >
                    Copy
                  </button>
                </div>
                <div className="text-sm font-mono text-gray-700">{block.service}</div>
                <pre className="text-sm font-mono bg-white p-3 rounded overflow-auto mt-2">
{block.content}
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Manual Guidance */}
      <div>
        <h3 className="text-xl font-semibold mb-4">Manual Guidance</h3>
        {manualGuidance.length === 0 ? (
          <p className="text-gray-500">No manual guidance available.</p>
        ) : (
          <div className="space-y-4">
            {manualGuidance.map((item, index) => (
              <div key={index} className="border rounded-lg p-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-start">
                    <AlertTriangle className="w-5 h-5 text-gray-500 mr-2" />
                    <h4 className="font-semibold text-lg text-gray-900">
                      {item.issue_type}
                    </h4>
                  </div>
                  <span className={`px-2 py-0.5 text-xs rounded-full
                    ${item.priority === 'high' ? 'bg-red-100 text-red-700'
                      : item.priority === 'medium' ? 'bg-yellow-100 text-yellow-700'
                      : 'bg-blue-100 text-blue-700'}`}>
                    {item.priority}
                  </span>
                </div>
                <p className="mt-2 text-gray-700">
                  {item.guidance}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default RemediationPanel;