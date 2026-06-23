import React from "react";
import { PieChart, Pie, Cell, Tooltip } from "recharts";
import StatCard from "./StatCard";

const ScoreCard = ({ scanData }) => {
  if (!scanData) return null;

  const score = scanData.security_score ?? 0;
  const risk = scanData.risk_level ?? "Unknown";

  const severity = scanData.severity_breakdown ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  const chartData = [
    {
      name: "Critical",
      value: severity.critical,
      color: "#dc2626",
    },
    {
      name: "High",
      value: severity.high,
      color: "#f97316",
    },
    {
      name: "Medium",
      value: severity.medium,
      color: "#eab308",
    },
    {
      name: "Low",
      value: severity.low,
      color: "#3b82f6",
    },
  ].filter((item) => item.value > 0);

  let scoreColor = "text-green-600";
  let badgeClass =
    "bg-green-100 text-green-700 border-green-300";

  if (score < 60) {
    scoreColor = "text-red-600";
    badgeClass =
      "bg-red-100 text-red-700 border-red-300";
  } else if (score < 80) {
    scoreColor = "text-yellow-600";
    badgeClass =
      "bg-yellow-100 text-yellow-700 border-yellow-300";
  }

  return (
    <div className="bg-white rounded-2xl shadow-xl p-10 mt-8">

      <h2 className="text-3xl font-bold text-center mb-12">
        AWS Security Score
      </h2>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-2 items-center">

        {/* Chart */}

        <div className="flex justify-center">

          {chartData.length > 0 ? (

            <PieChart width={380} height={380}>

              <Pie
                data={chartData}
                dataKey="value"
                cx="50%"
                cy="50%"
                innerRadius={85}
                outerRadius={135}
                paddingAngle={4}
              >
                {chartData.map((entry, index) => (
                  <Cell
                    key={index}
                    fill={entry.color}
                  />
                ))}
              </Pie>

              <Tooltip />

            </PieChart>

          ) : (

            <div className="text-center text-gray-500 text-xl">

              🎉

              <p className="mt-4 font-semibold">
                No Vulnerabilities
              </p>

            </div>

          )}

        </div>

        {/* Score */}

        <div className="flex flex-col items-center justify-center">

          <h1 className={`text-8xl font-black ${scoreColor}`}>
            {score}
            <span className="text-4xl text-gray-400">
              /100
            </span>
          </h1>

          <span
            className={`
              mt-6
              px-7
              py-3
              rounded-full
              font-bold
              border
              ${badgeClass}
            `}
          >
            {risk} Risk
          </span>

        </div>

      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mt-10">

        <StatCard
          title="Critical"
          value={severity.critical}
          color="red"
        />

        <StatCard
          title="High"
          value={severity.high}
          color="orange"
        />

        <StatCard
          title="Medium"
          value={severity.medium}
          color="yellow"
        />

        <StatCard
          title="Low"
          value={severity.low}
          color="blue"
        />

      </div>

    </div>
  );
};

export default ScoreCard;