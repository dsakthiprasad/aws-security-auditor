import React from "react";

const colorStyles = {
  red: {
    bg: "bg-red-50",
    border: "border-red-200",
    text: "text-red-700",
    value: "text-red-900",
    badge: "bg-red-500",
  },
  orange: {
    bg: "bg-orange-50",
    border: "border-orange-200",
    text: "text-orange-700",
    value: "text-orange-900",
    badge: "bg-orange-500",
  },
  yellow: {
    bg: "bg-yellow-50",
    border: "border-yellow-200",
    text: "text-yellow-700",
    value: "text-yellow-900",
    badge: "bg-yellow-500",
  },
  blue: {
    bg: "bg-blue-50",
    border: "border-blue-200",
    text: "text-blue-700",
    value: "text-blue-900",
    badge: "bg-blue-500",
  },
  green: {
    bg: "bg-green-50",
    border: "border-green-200",
    text: "text-green-700",
    value: "text-green-900",
    badge: "bg-green-500",
  },
};

const StatCard = ({ title, value, color = "blue" }) => {
  const style = colorStyles[color] || colorStyles.blue;

  return (
    <div
      className={`
        ${style.bg}
        ${style.border}
        border
        rounded-xl
        p-5
        shadow-sm
        hover:shadow-md
        transition-all
        duration-200
      `}
    >
      <div className="flex items-center justify-between">
        <h3 className={`font-semibold text-sm ${style.text}`}>
          {title}
        </h3>

        <div
          className={`w-3 h-3 rounded-full ${style.badge}`}
        />
      </div>

      <p className={`text-4xl font-bold mt-4 ${style.value}`}>
        {value}
      </p>
    </div>
  );
};

export default StatCard;