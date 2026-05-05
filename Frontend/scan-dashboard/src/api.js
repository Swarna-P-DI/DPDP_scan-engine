import axios from "axios";

const API_BASE_URL =
  import.meta.env.VITE_API_URL ||
  import.meta.env.REACT_APP_API_URL ||
  "http://127.0.0.1:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 120000,
});

const LONG_REQUEST_TIMEOUT_MS = 300000;
const STANDARD_REQUEST_TIMEOUT_MS = 120000;

export const startScan = () => api.get("/scan", { timeout: LONG_REQUEST_TIMEOUT_MS });

export const uploadScanFile = (file) => {
  const formData = new FormData();
  formData.append("file", file);
  return api.post("/scan", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
    timeout: LONG_REQUEST_TIMEOUT_MS,
  });
};

export const getStatus = (jobId) => api.get(`/status/${jobId}`, { timeout: STANDARD_REQUEST_TIMEOUT_MS });

export const getResult = (jobId) => api.get(`/result/${jobId}`, { timeout: LONG_REQUEST_TIMEOUT_MS });

export const getCoreReport = () => api.get("/report", { timeout: LONG_REQUEST_TIMEOUT_MS });

export const getRaidSummary = () => api.get("/raid_summary");

export const getComplianceReport = () => api.get("/compliance_report");

export const getHeatmap = () => api.get("/heatmap", { timeout: STANDARD_REQUEST_TIMEOUT_MS });

export const searchPii = (query) => api.post("/search_pii", { query });

export const getLogs = () => api.get("/logs");

export const summarizeLogs = (prompt) => api.post("/summarize_logs", { prompt });

const filenameFromDisposition = (disposition) => {
  const match = (disposition || "").match(/filename\*?=(?:UTF-8''|")?([^";]+)/i);
  return match ? decodeURIComponent(match[1].replace(/"$/, "")) : "";
};

export const downloadExport = async (jobId, format) => {
  const response = await fetch(`${API_BASE_URL}/exports/${encodeURIComponent(jobId)}/${encodeURIComponent(format)}`);
  if (!response.ok) {
    let message = "Export failed.";
    try {
      const payload = await response.json();
      message = payload.detail || message;
    } catch {
      message = response.statusText || message;
    }
    throw new Error(message);
  }

  return {
    blob: await response.blob(),
    contentType: response.headers.get("content-type") || "application/octet-stream",
    filename: filenameFromDisposition(response.headers.get("content-disposition")),
  };
};

export const buildFileUrl = (path) => {
  if (!path) return "";
  const normalized = path.replaceAll("\\", "/").replace(/^\/+/, "");
  return `${API_BASE_URL}/${normalized}`;
};

export default api;
