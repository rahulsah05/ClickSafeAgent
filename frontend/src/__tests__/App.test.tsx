import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import App from "../App";
import type { AnalysisResponse } from "../types/analysis";

const fetchMock = vi.fn();

const completedAnalysis: AnalysisResponse = {
  id: "analysis-123",
  submitted_url: "example.com",
  normalized_url: "https://example.com/",
  status: "completed",
  verdict: "Safe",
  risk_score: 8,
  explanation: "No high-confidence phishing indicators were detected.",
  evidence: {
    validation: {
      hostname: "example.com",
      scheme: "https",
      valid: true,
      fragment_removed: false
    },
    browser: {
      captured: true,
      final_url: "https://www.example.com/",
      status_code: 200,
      redirect_count: 1,
      redirects: [
        {
          url: "http://example.com/",
          status_code: 301,
          location: "https://www.example.com/"
        }
      ],
      screenshot_path: "C:\\private-artifacts\\analysis-123.png",
      html_size_bytes: 1280,
      html_truncated: false
    },
    ai: {
      provider: "openai_responses",
      model: "gpt-5.6",
      status: "completed",
      fallback_used: false,
      confidence: 0.92,
      recommended_action: "Proceed with normal caution.",
      evidence_weights: []
    },
    technical_analysis: [
      {
        source: "ssl",
        severity: "info",
        title: "Certificate is valid",
        description: "The certificate matches the destination host."
      }
    ],
    reputation: [
      {
        source: "virustotal",
        severity: "info",
        title: "No detections",
        description: "No provider detections were returned."
      }
    ],
    pending_capabilities: []
  },
  error_message: null,
  created_at: "2026-08-26T10:00:00Z",
  updated_at: "2026-08-26T10:00:01Z",
  completed_at: "2026-08-26T10:00:01Z"
};

const failedAnalysis: AnalysisResponse = {
  ...completedAnalysis,
  id: "failed-analysis",
  status: "failed",
  verdict: null,
  risk_score: null,
  explanation: null,
  evidence: {
    validation: {
      valid: true
    },
    browser: {
      captured: false,
      reason: "Browser navigation failed."
    }
  },
  error_message: "Browser navigation failed.",
  completed_at: "2026-08-26T10:00:01Z"
};

function jsonResponse(payload: AnalysisResponse) {
  return {
    ok: true,
    json: vi.fn().mockResolvedValue(payload)
  };
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  document.documentElement.classList.remove("dark");
});

test("renders the ClickSafe dashboard and accepts a bare domain", () => {
  render(<App />);

  expect(screen.getByText("ClickSafe")).toBeInTheDocument();
  expect(screen.getByLabelText("URL")).toHaveAttribute("type", "text");
  expect(screen.getByRole("button", { name: /analyze url/i })).toBeInTheDocument();
  expect(document.documentElement).toHaveClass("dark");

  fireEvent.click(screen.getByRole("button", { name: /toggle dark mode/i }));
  expect(document.documentElement).not.toHaveClass("dark");
});

test("submits a scan and renders the screenshot, redirect trail, and evidence groups", async () => {
  fetchMock.mockResolvedValueOnce(jsonResponse(completedAnalysis));
  render(<App />);

  fireEvent.change(screen.getByLabelText("URL"), { target: { value: "example.com" } });
  fireEvent.click(screen.getByRole("button", { name: /analyze url/i }));

  expect(screen.getByRole("status")).toHaveTextContent("Scanning");
  expect(screen.getByRole("button", { name: /scanning/i })).toBeDisabled();

  expect(await screen.findByText("Safe")).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledWith("http://127.0.0.1:8000/api/v1/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "example.com" })
  });
  expect(screen.getByText("Redirect Trail")).toBeInTheDocument();
  expect(screen.getByText("Step 1")).toBeInTheDocument();
  expect(screen.getByText("Location: https://www.example.com/")).toBeInTheDocument();
  expect(screen.getByText("Technical Analyzers")).toBeInTheDocument();
  expect(screen.getByText("Reputation")).toBeInTheDocument();
  expect(screen.getByAltText("Captured page screenshot")).toHaveAttribute(
    "src",
    "http://127.0.0.1:8000/api/v1/analyses/analysis-123/screenshot"
  );
  expect(screen.queryByText(/private-artifacts/)).not.toBeInTheDocument();

  fireEvent.error(screen.getByAltText("Captured page screenshot"));
  expect(screen.getByText("The captured screenshot is no longer available.")).toBeInTheDocument();
});

test("retries a transport failure using the last submitted URL", async () => {
  fetchMock.mockRejectedValueOnce(new Error("Network unavailable"));
  fetchMock.mockResolvedValueOnce(jsonResponse(completedAnalysis));
  render(<App />);

  fireEvent.change(screen.getByLabelText("URL"), { target: { value: "https://retry.example" } });
  fireEvent.click(screen.getByRole("button", { name: /analyze url/i }));

  expect(await screen.findByText("Network unavailable")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /retry scan/i }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  expect(fetchMock).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/v1/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://retry.example" })
  });
  expect(await screen.findByText("Safe")).toBeInTheDocument();
});

test("offers retry when a persisted analysis job fails", async () => {
  fetchMock.mockResolvedValueOnce(jsonResponse(failedAnalysis));
  fetchMock.mockResolvedValueOnce(jsonResponse(completedAnalysis));
  render(<App />);

  fireEvent.change(screen.getByLabelText("URL"), { target: { value: "example.com" } });
  fireEvent.click(screen.getByRole("button", { name: /analyze url/i }));

  expect(await screen.findByText("Browser navigation failed.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /retry scan/i })).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /retry scan/i }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  expect(await screen.findByText("Safe")).toBeInTheDocument();
});
