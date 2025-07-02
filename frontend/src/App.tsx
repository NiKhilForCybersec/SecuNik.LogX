import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import ErrorBoundary from './components/ErrorBoundary'

// Placeholder pages - create simple components for now as per batch requirements
const HomePage = () => (
  <div className="p-6">
    <h1 className="text-3xl font-bold text-white">Forensics Dashboard</h1>
    <p className="text-slate-400 mt-2">Digital forensics and log analysis platform</p>
  </div>
)

const AnalysisPage = () => (
  <div className="p-6">
    <h1 className="text-3xl font-bold text-white">Analysis</h1>
    <p className="text-slate-400 mt-2">Upload and analyze forensic evidence</p>
  </div>
)

const RulesPage = () => (
  <div className="p-6">
    <h1 className="text-3xl font-bold text-white">Detection Rules</h1>
    <p className="text-slate-400 mt-2">Manage YARA and Sigma detection rules</p>
  </div>
)

const ParsersPage = () => (
  <div className="p-6">
    <h1 className="text-3xl font-bold text-white">Log Parsers</h1>
    <p className="text-slate-400 mt-2">Create and manage custom log parsers</p>
  </div>
)

function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<HomePage />} />
            <Route path="analysis" element={<AnalysisPage />} />
            <Route path="rules" element={<RulesPage />} />
            <Route path="parsers" element={<ParsersPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  )
}

export default App