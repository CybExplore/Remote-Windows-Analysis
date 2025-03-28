// components/CircleSpinner.js
import { ProgressSpinner } from "primereact/progressspinner";

export const CircleSpinner = ({ size = '40px', strokeWidth = '4', message = '' }) => (
  <div className="flex flex-col items-center justify-center gap-2">
    <ProgressSpinner 
      style={{ 
        width: size, 
        height: size,
        animation: 'spin 1s linear infinite'
      }}
      strokeWidth={strokeWidth}
      animationDuration=".5s"
    />
    {message && <span className="text-sm text-gray-500">{message}</span>}
    
    <style jsx>{`
      @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
      }
    `}</style>
  </div>
);