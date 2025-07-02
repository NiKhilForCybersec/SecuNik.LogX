import React, { createContext, useContext, ReactNode } from 'react'
import toast, { Toaster, ToastOptions } from 'react-hot-toast'

interface NotificationContextType {
  success: (message: string, options?: ToastOptions) => void
  error: (message: string, options?: ToastOptions) => void
  info: (message: string, options?: ToastOptions) => void
  warning: (message: string, options?: ToastOptions) => void
  loading: (message: string, options?: ToastOptions) => string
  dismiss: (toastId?: string) => void
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined)

export const useNotification = () => {
  const context = useContext(NotificationContext)
  if (!context) {
    throw new Error('useNotification must be used within NotificationProvider')
  }
  return context
}

interface NotificationProviderProps {
  children: ReactNode
}

export const NotificationProvider: React.FC<NotificationProviderProps> = ({ children }) => {
  const defaultOptions: ToastOptions = {
    duration: 4000,
    position: 'bottom-right',
    style: {
      background: '#1e293b', // slate-800
      color: '#f1f5f9', // slate-100
      border: '1px solid #334155', // slate-700
    },
  }

  const success = (message: string, options?: ToastOptions) => {
    toast.success(message, {
      ...defaultOptions,
      ...options,
      iconTheme: {
        primary: '#10b981', // green-500
        secondary: '#f1f5f9',
      },
    })
  }

  const error = (message: string, options?: ToastOptions) => {
    toast.error(message, {
      ...defaultOptions,
      ...options,
      duration: 6000, // Errors show longer
      iconTheme: {
        primary: '#ef4444', // red-500
        secondary: '#f1f5f9',
      },
    })
  }

  const info = (message: string, options?: ToastOptions) => {
    toast(message, {
      ...defaultOptions,
      ...options,
      icon: '💡',
    })
  }

  const warning = (message: string, options?: ToastOptions) => {
    toast(message, {
      ...defaultOptions,
      ...options,
      icon: '⚠️',
      style: {
        ...defaultOptions.style,
        background: '#f59e0b', // amber-500
      },
    })
  }

  const loading = (message: string, options?: ToastOptions) => {
    return toast.loading(message, {
      ...defaultOptions,
      ...options,
    })
  }

  const dismiss = (toastId?: string) => {
    toast.dismiss(toastId)
  }

  return (
    <NotificationContext.Provider
      value={{ success, error, info, warning, loading, dismiss }}
    >
      {children}
      <Toaster />
    </NotificationContext.Provider>
  )
}