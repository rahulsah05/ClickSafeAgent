import axios from 'axios';
import { PredictResponse, ReportRequest, ReportResponse } from '@/types';

// ALWAYS use backend
const API_BASE_URL = "http://localhost:8000";

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Call /predict endpoint to check if URL is safe or scam
 */
export const predict = async (url: string): Promise<PredictResponse> => {
  const response = await apiClient.post<PredictResponse>('/predict', { url });
  return response.data;
};

/**
 * Call /report endpoint to report a suspicious URL
 */
export const report = async (request: ReportRequest): Promise<ReportResponse> => {
  const response = await apiClient.post<ReportResponse>('/report', request);
  return response.data;
};

/**
 * Get scan history from localStorage
 */
export const getHistory = () => {
  const stored = localStorage.getItem('clicksafe_history');
  if (!stored) return [];
  try {
    return JSON.parse(stored);
  } catch {
    return [];
  }
};

/**
 * Save scan history
 */
export const saveToHistory = (item: any) => {
  const history = getHistory();
  const updated = [item, ...history].slice(0, 50);
  localStorage.setItem('clicksafe_history', JSON.stringify(updated));
};

/**
 * Clear history
 */
export const clearHistory = () => {
  localStorage.removeItem('clicksafe_history');
};
