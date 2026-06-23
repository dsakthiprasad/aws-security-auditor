export default function StatusBadge({ variant = 'neutral', size = 'sm', children }) {
  // Base classes
  const baseClasses = 'rounded-full flex items-center gap-2';

  // Size classes
  const sizeClasses = {
    sm: 'px-2.5 py-0.5 text-xs',
    md: 'px-3 py-1 text-sm',
    lg: 'px-4 py-1.5 text-base',
  }[size] || 'px-2.5 py-0.5 text-xs';

  // Variant classes
  const variantClasses = {
    success: 'bg-green-100 text-green-800',
    error: 'bg-red-100 text-red-800',
    warning: 'bg-yellow-100 text-yellow-800',
    info: 'bg-blue-100 text-blue-800',
    neutral: 'bg-gray-100 text-gray-800',
  }[variant] || 'bg-gray-100 text-gray-800';

  return (
    <span className={`${baseClasses} ${sizeClasses} ${variantClasses}`}>
      {children}
    </span>
  );
}