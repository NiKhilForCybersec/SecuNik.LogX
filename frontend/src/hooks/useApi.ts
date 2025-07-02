import { useState, useCallback } from 'react'

interface UseApiState<T> {
  data: T | null
  loading: boolean
  error: Error | null
}

interface UseApiActions<T> {
  execute: (...args: any[]) => Promise<T | void>
  reset: () => void
}

export function useApi<T = any>(
  apiFunction: (...args: any[]) => Promise<T>
): UseApiState<T> & UseApiActions<T> {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: false,
    error: null,
  })

  const execute = useCallback(
    async (...args: any[]): Promise<T | void> => {
      setState({ data: null, loading: true, error: null })
      
      try {
        const result = await apiFunction(...args)
        setState({ data: result, loading: false, error: null })
        return result
      } catch (error) {
        const apiError = error instanceof Error ? error : new Error('An error occurred')
        setState({ data: null, loading: false, error: apiError })
        throw apiError
      }
    },
    [apiFunction]
  )

  const reset = useCallback(() => {
    setState({ data: null, loading: false, error: null })
  }, [])

  return {
    ...state,
    execute,
    reset,
  }
}

// Hook for mutations (POST, PUT, DELETE)
export function useMutation<T = any, V = any>(
  mutationFunction: (variables: V) => Promise<T>
) {
  const [state, setState] = useState<{
    data: T | null
    loading: boolean
    error: Error | null
  }>({
    data: null,
    loading: false,
    error: null,
  })

  const mutate = useCallback(
    async (variables: V): Promise<T> => {
      setState({ data: null, loading: true, error: null })
      
      try {
        const result = await mutationFunction(variables)
        setState({ data: result, loading: false, error: null })
        return result
      } catch (error) {
        const apiError = error instanceof Error ? error : new Error('Mutation failed')
        setState({ data: null, loading: false, error: apiError })
        throw apiError
      }
    },
    [mutationFunction]
  )

  return {
    ...state,
    mutate,
  }
}