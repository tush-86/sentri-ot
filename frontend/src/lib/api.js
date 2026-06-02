const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';
const authHeaders = import.meta.env.VITE_SENTRI_OT_API_KEY
  ? { 'X-API-Key': import.meta.env.VITE_SENTRI_OT_API_KEY }
  : {};

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...authHeaders, ...(options.headers || {}) },
    ...options
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed: ${response.status}`);
  }

  return response.json();
}

export const api = {
  // Existing endpoints
  getSummary: () => request('/api/stats/summary'),
  getLatestScan: () => request('/api/scan/latest/result'),
  getCompliance: () => request('/api/compliance/latest'),
  getAlerts: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.page) params.set('page', filters.page);
    if (filters.per_page) params.set('per_page', filters.per_page);
    if (filters.severity) params.set('severity', filters.severity);
    return request(`/api/alerts?${params.toString()}`).then((data) => ({
      ...data,
      alerts: data.alerts || data.items || [],
      total: data.total || (data.items || data.alerts || []).length,
    }));
  },
  getScanHistory: () => request('/api/scan/history'),
  startScan: () => request('/api/scan/start', { method: 'POST' }),
  getScanStatus: () => request('/api/scan/status'),
  downloadReport: async () => {
    const response = await fetch(`${API_BASE_URL}/api/report/pdf`, { headers: authHeaders });
    if (!response.ok) {
      const message = await response.text();
      throw new Error(message || `Report download failed: ${response.status}`);
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'sentri-ot-report.pdf';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },

  // New endpoints for scale
  getAssets: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.page) params.set('page', filters.page);
    if (filters.per_page) params.set('per_page', filters.per_page);
    if (filters.search) params.set('search', filters.search);
    if (filters.protocol) params.set('protocol', filters.protocol);
    if (filters.zone) params.set('segmentation_zone', filters.zone);
    if (filters.criticality) params.set('criticality', filters.criticality);
    return request(`/api/assets?${params.toString()}`);
  },
  getAssetById: (id) => request(`/api/assets/${id}`),
  getAssetStats: () => request('/api/assets/stats'),
  acknowledgeAlert: (id) => request(`/api/alerts/${id}/acknowledge`, { method: 'PUT' }),
  getComplianceFrameworks: () => request('/api/compliance/frameworks'),
  getComplianceControls: (framework = 'DESC') => request(`/api/compliance/controls?framework=${framework}`),
  getConfig: () => request('/api/config'),
  updateConfig: (config) => request('/api/config', { method: 'PUT', body: JSON.stringify(config) }),
  getHealth: () => request('/api/health'),
};
