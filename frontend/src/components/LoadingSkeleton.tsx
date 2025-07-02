import clsx from 'clsx'

interface SkeletonProps {
  className?: string
  variant?: 'text' | 'circular' | 'rectangular' | 'card'
  width?: string | number
  height?: string | number
  count?: number
}

export function Skeleton({ 
  className, 
  variant = 'text', 
  width, 
  height,
  count = 1 
}: SkeletonProps) {
  const baseClass = 'animate-pulse bg-slate-800'
  
  const variantClasses = {
    text: 'h-4 rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-lg',
    card: 'rounded-lg'
  }
  
  const defaultSizes = {
    text: { width: '100%', height: '1rem' },
    circular: { width: '2.5rem', height: '2.5rem' },
    rectangular: { width: '100%', height: '8rem' },
    card: { width: '100%', height: '12rem' }
  }
  
  const size = defaultSizes[variant]
  
  return (
    <>
      {Array.from({ length: count }).map((_, index) => (
        <div
          key={index}
          className={clsx(baseClass, variantClasses[variant], className)}
          style={{
            width: width || size.width,
            height: height || size.height,
            marginBottom: count > 1 && index < count - 1 ? '0.5rem' : undefined
          }}
        />
      ))}
    </>
  )
}

// Composite skeletons
export function AnalysisCardSkeleton() {
  return (
    <div className="bg-slate-900 rounded-lg p-6 border border-slate-800">
      <div className="flex justify-between items-start mb-4">
        <div className="flex-1">
          <Skeleton variant="text" width="60%" className="mb-2" />
          <Skeleton variant="text" width="40%" height="0.875rem" />
        </div>
        <Skeleton variant="circular" width="2rem" height="2rem" />
      </div>
      <div className="flex items-center space-x-4 mb-4">
        <Skeleton variant="text" width="4rem" />
        <Skeleton variant="text" width="5rem" />
        <Skeleton variant="text" width="3rem" />
      </div>
      <Skeleton variant="rectangular" height="0.5rem" />
    </div>
  )
}

export function TableRowSkeleton({ columns }: { columns: number }) {
  return (
    <tr>
      {Array.from({ length: columns }).map((_, index) => (
        <td key={index} className="px-6 py-4">
          <Skeleton variant="text" />
        </td>
      ))}
    </tr>
  )
}

export function DashboardStatsSkeleton() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {Array.from({ length: 4 }).map((_, index) => (
        <div key={index} className="bg-slate-900 rounded-lg p-6 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <Skeleton variant="circular" width="2rem" height="2rem" />
            <Skeleton variant="text" width="3rem" />
          </div>
          <Skeleton variant="text" width="50%" />
        </div>
      ))}
    </div>
  )
}