import { useEffect, useState } from 'react'
import clsx from 'clsx'

interface ProgressRingProps {
  progress: number
  size?: number
  strokeWidth?: number
  className?: string
  showLabel?: boolean
  labelSize?: 'sm' | 'md' | 'lg' | 'xl'
  animate?: boolean
  animationDuration?: number
  colors?: {
    low?: string
    medium?: string
    high?: string
    complete?: string
  }
}

export default function ProgressRing({
  progress,
  size = 120,
  strokeWidth = 8,
  className,
  showLabel = true,
  labelSize = 'lg',
  animate = true,
  animationDuration = 1000,
  colors = {
    low: '#ef4444',      // red
    medium: '#f59e0b',   // amber
    high: '#3b82f6',     // blue
    complete: '#10b981'  // green
  }
}: ProgressRingProps) {
  const [animatedProgress, setAnimatedProgress] = useState(animate ? 0 : progress)
  
  // Ensure progress is between 0 and 100
  const normalizedProgress = Math.min(100, Math.max(0, progress))
  
  // Calculate dimensions
  const radius = (size - strokeWidth) / 2
  const circumference = radius * 2 * Math.PI
  const offset = circumference - (animatedProgress / 100) * circumference

  useEffect(() => {
    if (animate) {
      const timer = setTimeout(() => {
        setAnimatedProgress(normalizedProgress)
      }, 100)
      return () => clearTimeout(timer)
    } else {
      setAnimatedProgress(normalizedProgress)
    }
  }, [normalizedProgress, animate])

  // Determine color based on progress
  const getProgressColor = () => {
    if (normalizedProgress === 100) return colors.complete
    if (normalizedProgress >= 70) return colors.high
    if (normalizedProgress >= 40) return colors.medium
    return colors.low
  }

  // Get label font size classes
  const getLabelSizeClasses = () => {
    switch (labelSize) {
      case 'sm':
        return 'text-sm'
      case 'md':
        return 'text-base'
      case 'lg':
        return 'text-lg'
      case 'xl':
        return 'text-xl'
      default:
        return 'text-lg'
    }
  }

  const progressColor = getProgressColor()

  return (
    <div className={clsx('relative inline-flex items-center justify-center', className)}>
      <svg
        width={size}
        height={size}
        className="transform -rotate-90"
      >
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={strokeWidth}
          fill="none"
          className="text-slate-800"
        />
        
        {/* Progress circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={progressColor}
          strokeWidth={strokeWidth}
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all"
          style={{
            transitionDuration: animate ? `${animationDuration}ms` : '0ms',
            transitionProperty: 'stroke-dashoffset, stroke',
            transitionTimingFunction: 'cubic-bezier(0.4, 0, 0.2, 1)'
          }}
        />
        
        {/* Animated glow effect for high progress */}
        {animatedProgress >= 70 && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={progressColor}
            strokeWidth={strokeWidth}
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            opacity="0.3"
            className="animate-pulse"
          />
        )}
      </svg>
      
      {/* Center content */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {showLabel && (
          <>
            <span 
              className={clsx(
                'font-bold text-white',
                getLabelSizeClasses()
              )}
              style={{ color: progressColor }}
            >
              {Math.round(animatedProgress)}%
            </span>
            {normalizedProgress === 100 && (
              <span className="text-xs text-slate-400 mt-1">Complete</span>
            )}
          </>
        )}
      </div>
      
      {/* Additional decorative elements */}
      {normalizedProgress === 100 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div 
            className="absolute w-full h-full rounded-full animate-ping"
            style={{ 
              backgroundColor: progressColor,
              opacity: 0.1,
              animationDuration: '2s'
            }}
          />
        </div>
      )}
    </div>
  )
}

// Export a compound component for more complex use cases
export function ProgressRingWithStats({
  progress,
  title,
  subtitle,
  stats,
  size = 140,
  className
}: {
  progress: number
  title: string
  subtitle?: string
  stats?: { label: string; value: string | number }[]
  size?: number
  className?: string
}) {
  return (
    <div className={clsx('bg-slate-900 rounded-lg p-6 border border-slate-800', className)}>
      <div className="flex items-center space-x-6">
        <ProgressRing 
          progress={progress} 
          size={size}
          animate
        />
        
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-white mb-1">{title}</h3>
          {subtitle && (
            <p className="text-sm text-slate-400 mb-4">{subtitle}</p>
          )}
          
          {stats && stats.length > 0 && (
            <div className="grid grid-cols-2 gap-3">
              {stats.map((stat, index) => (
                <div key={index}>
                  <div className="text-2xl font-bold text-white">
                    {stat.value}
                  </div>
                  <div className="text-xs text-slate-400">
                    {stat.label}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}