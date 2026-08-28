import { expect, test } from "@playwright/test";

test("submits a URL and presents the completed verdict", async ({ page }) => {
  await page.route("**/api/v1/analyze", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        id: "e2e-analysis-123",
        submitted_url: "example.com",
        normalized_url: "https://example.com/",
        status: "completed",
        verdict: "Safe",
        risk_score: 12,
        explanation: "No high-confidence phishing indicators were detected.",
        evidence: {
          validation: {
            hostname: "example.com",
            scheme: "https",
            valid: true,
            fragment_removed: false
          },
          browser: {
            captured: false,
            final_url: "https://example.com/",
            status_code: 200,
            redirect_count: 0,
            redirects: [],
            html_size_bytes: 0,
            html_truncated: false
          },
          ai: {
            provider: "openai_responses",
            model: "gpt-5.6",
            status: "completed",
            fallback_used: false,
            confidence: 0.9,
            recommended_action: "Proceed with normal caution.",
            evidence_weights: []
          },
          technical_analysis: [],
          reputation: [],
          pending_capabilities: []
        },
        error_message: null,
        created_at: "2026-08-28T12:00:00Z",
        updated_at: "2026-08-28T12:00:01Z",
        completed_at: "2026-08-28T12:00:01Z"
      })
    });
  });

  await page.goto("/");
  await page.getByLabel("URL").fill("example.com");
  await page.getByRole("button", { name: "Analyze URL" }).click();

  await expect(page.getByText("Safe", { exact: true })).toBeVisible();
  await expect(page.getByText("12/100", { exact: true })).toBeVisible();
  await expect(page.getByText("Final destination:")).toBeVisible();
  await expect(page.getByText("AI Assessment")).toBeVisible();
});
