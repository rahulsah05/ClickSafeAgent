import { PredictResponse, ReportResponse, ReportRequest } from '@/types';

// Simple hash function for deterministic results
const hashString = (str: string): number => {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash);
};

const urlRules = [
  'no_https',
  'url_shortener',
  'suspicious_tld',
  'excessive_subdomains',
  'ip_address',
  'misleading_domain',
  'suspicious_port',
];

const safeExplanations = [
  'Uses HTTPS protocol',
  'Domain has valid SSL certificate',
  'Established domain age',
  'Clean reputation score',
];

const scamExplanations = [
  'Contains URL shortener',
  'No HTTPS protocol',
  'Suspicious domain pattern',
  'Recently registered domain',
  'Mimics known brand',
  'Uses uncommon TLD',
];

export const mockPredict = async (url: string): Promise<PredictResponse> => {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 800));

  const hash = hashString(url);
  const isScam = hash % 3 === 0; // ~33% scam rate
  const confidence = 0.7 + (hash % 30) / 100;

  const matchedRules = isScam 
    ? urlRules.slice(0, (hash % 3) + 1)
    : [];

  const explanation = isScam
    ? scamExplanations.slice(0, (hash % 4) + 1)
    : safeExplanations.slice(0, (hash % 3) + 1);

  return {
    url,
    label: isScam ? 'scam' : 'safe',
    confidence: Number(confidence.toFixed(2)),
    rules: matchedRules,
    explanation,
  };
};

export const mockReport = async (request: ReportRequest): Promise<ReportResponse> => {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 500));

  return {
    ok: true,
    id: `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
  };
};
