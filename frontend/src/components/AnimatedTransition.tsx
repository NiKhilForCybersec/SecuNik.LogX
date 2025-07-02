import { motion, AnimatePresence } from 'framer-motion'
import { ReactNode } from 'react'

interface AnimatedTransitionProps {
  children: ReactNode
  className?: string
}

// Page transition wrapper
export function PageTransition({ children, className }: AnimatedTransitionProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.3 }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

// Stagger children animation
export function StaggerChildren({ children, className }: AnimatedTransitionProps) {
  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={{
        visible: {
          transition: {
            staggerChildren: 0.1
          }
        }
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

// Individual stagger item
export function StaggerItem({ children, className }: AnimatedTransitionProps) {
  return (
    <motion.div
      variants={{
        hidden: { opacity: 0, y: 20 },
        visible: { opacity: 1, y: 0 }
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

// Fade in animation
export function FadeIn({ 
  children, 
  className,
  delay = 0,
  duration = 0.5 
}: AnimatedTransitionProps & { delay?: number; duration?: number }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay, duration }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

// Scale animation
export function ScaleIn({ children, className }: AnimatedTransitionProps) {
  return (
    <motion.div
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: "spring", stiffness: 260, damping: 20 }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

// Slide in animation
export function SlideIn({ 
  children, 
  className,
  direction = 'left' 
}: AnimatedTransitionProps & { direction?: 'left' | 'right' | 'up' | 'down' }) {
  const variants = {
    left: { x: -50 },
    right: { x: 50 },
    up: { y: -50 },
    down: { y: 50 }
  }
  
  return (
    <motion.div
      initial={{ opacity: 0, ...variants[direction] }}
      animate={{ opacity: 1, x: 0, y: 0 }}
      transition={{ duration: 0.3 }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

// Loading spinner
export function LoadingSpinner({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const sizes = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12'
  }
  
  return (
    <motion.div
      animate={{ rotate: 360 }}
      transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
      className={`${sizes[size]} border-2 border-blue-500 border-t-transparent rounded-full`}
    />
  )
}

// Progress bar animation
export function AnimatedProgress({ progress }: { progress: number }) {
  return (
    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${progress}%` }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="h-full bg-gradient-to-r from-blue-500 to-purple-600"
      />
    </div>
  )
}