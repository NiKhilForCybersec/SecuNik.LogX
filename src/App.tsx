import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import UploadAnalyze from './pages/UploadAnalyze'
import ParserStudio from './pages/ParserStudio'
import RuleManager from './pages/RuleManager'
import AnalysisResults from './pages/AnalysisResults'
import History from './pages/History'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/upload" element={<UploadAnalyze />} />
        <Route path="/parsers" element={<ParserStudio />} />
        <Route path="/rules" element={<RuleManager />} />
        <Route path="/analysis/:id?" element={<AnalysisResults />} />
        <Route path="/history" element={<History />} />
      </Routes>
    </Layout>
  )
}

export default App