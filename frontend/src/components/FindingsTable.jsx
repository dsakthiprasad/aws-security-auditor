import React from "react";

const FindingsTable = ({ findings }) => {
  if (!findings || findings.length === 0) {
    return (
      <div className="bg-white rounded-2xl shadow-xl p-8 mt-8">
        <h2 className="text-2xl font-bold mb-6">
          Security Findings
        </h2>

        <div className="text-center text-gray-500 py-10">
          🎉 No security findings detected.
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl shadow-xl p-8 mt-8">
      <h2 className="text-2xl font-bold mb-6">
        Security Findings
      </h2>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th
                scope="col"
                className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
              >
                Scanner
              </th>
              <th
                scope="col"
                className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
              >
                Issue
              </th>
              <th
                scope="col"
                className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
              >
                User / Resource
              </th>
              <th
                scope="col"
                className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
              >
                Details
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {findings.map((finding) => {
              const data = finding.finding_data || {};

              const issue =
                finding.issue_type ||
                data.issue ||
                "Unknown";

              const resource =
                data.user ||
                data.bucket ||
                data.group ||
                data.resource ||
                "-";

              const details =
                data.details ||
                "-";

              // Determine scanner badge color
              let scannerClass = "bg-gray-100 text-gray-800";
              if (finding.scanner === "IAM") {
                scannerClass = "bg-purple-100 text-purple-800";
              } else if (finding.scanner === "S3") {
                scannerClass = "bg-blue-100 text-blue-800";
              } else if (finding.scanner === "Security Group") {
                scannerClass = "bg-orange-100 text-orange-800";
              }

              return (
                <tr
                  key={finding.id}
                  className="hover:bg-gray-50 transition-colors"
                >
                  <td className="px-6 py-4 font-semibold capitalize whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${scannerClass}`}>
                      {finding.scanner}
                    </span>
                  </td>

                  <td className="px-6 py-4 font-semibold text-gray-900">
                    {issue}
                  </td>

                  <td className="px-6 py-4 font-mono text-sm">
                    <span className="bg-gray-50 rounded-full px-2 py-0.5">
                      {resource}
                    </span>
                  </td>

                  <td className="px-6 py-4">
                    <div className="bg-gray-50 rounded-sm p-3 text-sm text-gray-700">
                      {details}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default FindingsTable;