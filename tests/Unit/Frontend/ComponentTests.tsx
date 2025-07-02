import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import '@testing-library/jest-dom'

// Components to test
import { AnalysisCard } from '../../frontend/src/components/AnalysisCard'
import { FileUpload } from '../../frontend/src/components/FileUpload'
import { DataTable } from '../../frontend/src/components/DataTable'
import { SearchFilter } from '../../frontend/src/components/SearchFilter'
import { LoadingSkeleton } from '../../frontend/src/components/LoadingSkeleton'

// Mock dependencies
jest.mock('../../frontend/src/store/useAnalysisStore', () => ({
  useAnalysisStore: () => ({
    analyses: [],
    setFilter: jest.fn(),
    filter: { status: 'all', threatLevel: 'all' }
  })
}))

jest.mock('../../frontend/src/contexts/NotificationContext', () => ({
  useNotification: () => ({
    success: jest.fn(),
    error: jest.fn(),
    info: jest.fn()
  })
}))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false },
    mutations: { retry: false }
  }
})

const renderWithProviders = (component: React.ReactElement) => {
  return render(
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {component}
      </BrowserRouter>
    </QueryClientProvider>
  )
}

describe('AnalysisCard', () => {
  const mockAnalysis = {
    id: '123',
    fileName: 'test.log',
    status: 'completed',
    progress: 100,
    threatLevel: 'high',
    createdAt: '2025-01-01T00:00:00Z',
    iocCount: 25,
    mitreCount: 10
  }

  it('renders analysis information correctly', () => {
    renderWithProviders(<AnalysisCard analysis={mockAnalysis} />)
    
    expect(screen.getByText('test.log')).toBeInTheDocument()
    expect(screen.getByText('high')).toBeInTheDocument()
    expect(screen.getByText('25 IOCs')).toBeInTheDocument()
    expect(screen.getByText('10 MITRE')).toBeInTheDocument()
  })

  it('shows progress bar when processing', () => {
    const processingAnalysis = { ...mockAnalysis, status: 'processing', progress: 45 }
    renderWithProviders(<AnalysisCard analysis={processingAnalysis} />)
    
    expect(screen.getByText('45%')).toBeInTheDocument()
    expect(screen.getByRole('progressbar')).toBeInTheDocument()
  })

  it('handles delete action', async () => {
    const onDelete = jest.fn()
    renderWithProviders(<AnalysisCard analysis={mockAnalysis} onDelete={onDelete} />)
    
    const deleteButton = screen.getByLabelText('Delete analysis')
    await userEvent.click(deleteButton)
    
    expect(onDelete).toHaveBeenCalledWith('123')
  })
})

describe('FileUpload', () => {
  it('accepts valid file types', async () => {
    const onUpload = jest.fn()
    renderWithProviders(<FileUpload onUpload={onUpload} />)
    
    const file = new File(['log content'], 'test.log', { type: 'text/plain' })
    const input = screen.getByLabelText('Upload file')
    
    await userEvent.upload(input, file)
    
    expect(onUpload).toHaveBeenCalledWith(file)
  })

  it('rejects files over size limit', async () => {
    renderWithProviders(<FileUpload onUpload={jest.fn()} />)
    
    // Create 101MB file (over 100MB limit)
    const largeFile = new File(['x'.repeat(101 * 1024 * 1024)], 'large.log')
    const input = screen.getByLabelText('Upload file')
    
    await userEvent.upload(input, largeFile)
    
    expect(screen.getByText(/exceeds.*limit/i)).toBeInTheDocument()
  })

  it('shows drag and drop state', async () => {
    renderWithProviders(<FileUpload onUpload={jest.fn()} />)
    
    const dropZone = screen.getByTestId('drop-zone')
    
    fireEvent.dragEnter(dropZone)
    expect(dropZone).toHaveClass('border-blue-500')
    
    fireEvent.dragLeave(dropZone)
    expect(dropZone).not.toHaveClass('border-blue-500')
  })
})

describe('DataTable', () => {
  const mockData = [
    { id: 1, type: 'ipv4', value: '192.168.1.1', confidence: 95 },
    { id: 2, type: 'domain', value: 'malicious.com', confidence: 87 },
    { id: 3, type: 'hash', value: 'abc123def456', confidence: 100 }
  ]

  const columns = [
    { key: 'type', label: 'Type' },
    { key: 'value', label: 'Value' },
    { key: 'confidence', label: 'Confidence' }
  ]

  it('renders table with data', () => {
    renderWithProviders(<DataTable data={mockData} columns={columns} />)
    
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument()
    expect(screen.getByText('malicious.com')).toBeInTheDocument()
    expect(screen.getByText('abc123def456')).toBeInTheDocument()
  })

  it('sorts data when column header clicked', async () => {
    renderWithProviders(<DataTable data={mockData} columns={columns} />)
    
    const typeHeader = screen.getByText('Type')
    await userEvent.click(typeHeader)
    
    const rows = screen.getAllByRole('row')
    expect(rows[1]).toHaveTextContent('domain') // First data row after sort
  })

  it('filters data based on search input', async () => {
    renderWithProviders(<DataTable data={mockData} columns={columns} />)
    
    const searchInput = screen.getByPlaceholderText('Search...')
    await userEvent.type(searchInput, 'malicious')
    
    expect(screen.getByText('malicious.com')).toBeInTheDocument()
    expect(screen.queryByText('192.168.1.1')).not.toBeInTheDocument()
  })

  it('paginates data correctly', async () => {
    const largeData = Array.from({ length: 25 }, (_, i) => ({
      id: i,
      type: 'test',
      value: `item-${i}`,
      confidence: 90
    }))
    
    renderWithProviders(
      <DataTable data={largeData} columns={columns} pageSize={10} />
    )
    
    expect(screen.getByText('item-0')).toBeInTheDocument()
    expect(screen.queryByText('item-10')).not.toBeInTheDocument()
    
    const nextButton = screen.getByLabelText('Next page')
    await userEvent.click(nextButton)
    
    expect(screen.queryByText('item-0')).not.toBeInTheDocument()
    expect(screen.getByText('item-10')).toBeInTheDocument()
  })
})

describe('SearchFilter', () => {
  it('updates filters when changed', async () => {
    const onFilterChange = jest.fn()
    renderWithProviders(<SearchFilter onFilterChange={onFilterChange} />)
    
    const statusSelect = screen.getByLabelText('Status')
    await userEvent.selectOptions(statusSelect, 'completed')
    
    expect(onFilterChange).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'completed' })
    )
  })

  it('debounces search input', async () => {
    jest.useFakeTimers()
    const onFilterChange = jest.fn()
    renderWithProviders(<SearchFilter onFilterChange={onFilterChange} />)
    
    const searchInput = screen.getByPlaceholderText('Search analyses...')
    await userEvent.type(searchInput, 'test')
    
    expect(onFilterChange).not.toHaveBeenCalled()
    
    jest.advanceTimersByTime(300)
    
    expect(onFilterChange).toHaveBeenCalledWith(
      expect.objectContaining({ search: 'test' })
    )
    
    jest.useRealTimers()
  })
})

describe('LoadingSkeleton', () => {
  it('renders correct variant', () => {
    const { container } = render(<LoadingSkeleton variant="text" />)
    expect(container.firstChild).toHaveClass('h-4')
    
    const { container: circleContainer } = render(<LoadingSkeleton variant="circular" />)
    expect(circleContainer.firstChild).toHaveClass('rounded-full')
  })

  it('renders multiple skeletons when count specified', () => {
    render(<LoadingSkeleton variant="text" count={3} />)
    const skeletons = screen.getAllByTestId('skeleton')
    expect(skeletons).toHaveLength(3)
  })
})