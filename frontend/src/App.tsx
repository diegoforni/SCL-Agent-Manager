import { useState, useEffect } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { AgentsPage } from './pages/AgentsPage';
import { TopologyPage } from './pages/TopologyPage';
import { SettingsPage } from './pages/SettingsPage';
import { DefenderPage } from './pages/DefenderPage';
import { ReplayPage } from './pages/ReplayPage';
import './index.css';

function App() {
  return (
    <HashRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Navigate to="/agents" replace />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/topology" element={<TopologyPage />} />
          <Route path="/defender" element={<DefenderPage />} />
          <Route path="/replay" element={<ReplayPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}

export default App;
