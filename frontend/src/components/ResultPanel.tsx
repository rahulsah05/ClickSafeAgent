import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  FileSearch,
  RotateCcw,
  ShieldQuestion,
  XCircle
} from "lucide-react";
import { useState } from "react";

import { getAnalysisScreenshotUrl } from "../lib/api";
import type { AnalysisResponse, AnalysisStatus, Verdict } from "../types/analysis";

interface ResultPanelProps {
  error: string | null;
  isLoading: boolean;
  onRetry: () => void;
  result: AnalysisResponse | null;
}

const verdictStyles: Record<Verdict, string> = {
  Safe: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-300",
  Suspicious: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-300",
  Malicious: "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300"
};

const riskBarStyles: Record<Verdict, string> = {
  Safe: "bg-emerald-500",
  Suspicious: "bg-amber-500",
  Malicious: "bg-red-500"
};

const statusStyles: Record<AnalysisStatus, string> = {
  requested:
    "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950 dark:text-sky-300",
  running:
    "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-300",
  completed:
    "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-300",
  failed:
    "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300"
};

export function ResultPanel({ error, isLoading, onRetry, result }: ResultPanelProps) {
  return (
    <section className="min-h-[440px] rounded-lg border border-zinc-200 bg-white p-5 shadow-soft dark:border-zinc-800 dark:bg-zinc-900">
      <div className="mb-5 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-normal">Verdict</h2>
          <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Risk score and evidence</p>
        </div>
        <FileSearch aria-hidden="true" className="text-zinc-400" size={22} />
      </div>

      {isLoading ? <LoadingState /> : null}
      {!isLoading && error ? <ErrorState message={error} onRetry={onRetry} /> : null}
      {!isLoading && !error && result ? <VerdictState onRetry={onRetry} result={result} /> : null}
      {!isLoading && !error && !result ? <EmptyState /> : null}
    </section>
  );
}

function EmptyState() {
  return (
    <div className="flex min-h-[320px] flex-col items-center justify-center rounded-lg border border-dashed border-zinc-200 bg-slate-50 p-6 text-center dark:border-zinc-800 dark:bg-zinc-950">
      <ShieldQuestion aria-hidden="true" className="mb-3 text-zinc-400" size={34} />
      <p className="text-sm font-medium text-zinc-600 dark:text-zinc-300">Awaiting scan</p>
    </div>
  );
}

function LoadingState() {
  return (
    <div
      aria-live="polite"
      className="flex min-h-[320px] flex-col items-center justify-center rounded-lg border border-zinc-200 bg-slate-50 p-6 text-center dark:border-zinc-800 dark:bg-zinc-950"
      role="status"
    >
      <Clock3 aria-hidden="true" className="mb-3 animate-pulse text-emerald-500" size={34} />
      <p className="text-sm font-medium text-zinc-600 dark:text-zinc-300">Scanning</p>
    </div>
  );
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div
      className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200"
      role="alert"
    >
      <div className="flex gap-3">
        <AlertTriangle aria-hidden="true" className="mt-0.5 shrink-0" size={18} />
        <div>
          <p className="text-sm leading-6">{message}</p>
          <RetryButton onRetry={onRetry} />
        </div>
      </div>
    </div>
  );
}

function VerdictState({ onRetry, result }: { onRetry: () => void; result: AnalysisResponse }) {
  const badgeLabel = result.verdict ?? titleCase(result.status);
  const badgeClass = result.verdict ? verdictStyles[result.verdict] : statusStyles[result.status];
  const BadgeIcon = result.status === "failed" ? XCircle : CheckCircle2;
  const validation = getRecord(result.evidence.validation);
  const browser = getRecord(result.evidence.browser);
  const ai = getRecord(result.evidence.ai);
  const technicalAnalysis = getRecordArray(result.evidence.technical_analysis);
  const reputation = getRecordArray(result.evidence.reputation);
  const redirects = getRecordArray(browser?.redirects);
  const pendingCapabilities = Array.isArray(result.evidence.pending_capabilities)
    ? result.evidence.pending_capabilities
    : [];
  const screenshotUrl = browser?.captured === true ? getAnalysisScreenshotUrl(result.id) : null;

  return (
    <div className="space-y-5">
      <div
        className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-semibold ${badgeClass}`}
      >
        <BadgeIcon aria-hidden="true" size={18} />
        {badgeLabel}
      </div>

      <div>
        <div className="mb-2 flex items-center justify-between text-sm">
          <span className="font-medium text-zinc-600 dark:text-zinc-300">Risk score</span>
          <span className="font-semibold">
            {result.risk_score === null ? "Pending" : `${result.risk_score}/100`}
          </span>
        </div>
        <div className="h-3 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
          <div
            className={`h-full rounded-full transition-all ${
              result.verdict ? riskBarStyles[result.verdict] : "bg-zinc-400"
            }`}
            style={{ width: `${result.risk_score ?? 0}%` }}
          />
        </div>
      </div>

      <div>
        <p className="text-sm leading-6 text-zinc-600 dark:text-zinc-300">
          {result.error_message ?? result.explanation}
        </p>
        {result.status === "failed" ? <RetryButton onRetry={onRetry} /> : null}
      </div>

      <dl className="grid gap-x-5 gap-y-3 border-t border-zinc-200 pt-4 text-sm dark:border-zinc-800 sm:grid-cols-2">
        <InfoRow label="Submitted" value={result.submitted_url} />
        <InfoRow label="Normalized" value={result.normalized_url ?? "Not available"} />
        <InfoRow label="Job ID" value={result.id} />
        <InfoRow label="Completed" value={formatDate(result.completed_at)} />
      </dl>

      {validation ? (
        <div className="border-t border-zinc-200 pt-4 dark:border-zinc-800">
          <h3 className="text-sm font-semibold tracking-normal">Validation Evidence</h3>
          <div className="mt-3 grid gap-2 text-sm text-zinc-600 dark:text-zinc-300 sm:grid-cols-2">
            <span>Host: {String(validation.hostname ?? "n/a")}</span>
            <span>Scheme: {String(validation.scheme ?? "n/a")}</span>
            <span>Valid: {String(validation.valid ?? false)}</span>
            <span>Fragment removed: {String(validation.fragment_removed ?? false)}</span>
          </div>
        </div>
      ) : null}

      {browser ? (
        <div className="border-t border-zinc-200 pt-4 dark:border-zinc-800">
          <h3 className="text-sm font-semibold tracking-normal">Browser Capture</h3>
          <div className="mt-3 grid gap-2 text-sm text-zinc-600 dark:text-zinc-300 sm:grid-cols-2">
            <span>Captured: {String(browser.captured ?? false)}</span>
            <span>Status: {formatUnknown(browser.status_code)}</span>
            <span className="break-words">Final URL: {formatUnknown(browser.final_url)}</span>
            <span>Redirects: {formatUnknown(browser.redirect_count)}</span>
            <span>HTML size: {formatBytes(browser.html_size_bytes)}</span>
            <span>HTML truncated: {String(browser.html_truncated ?? false)}</span>
          </div>

          <RedirectTrail finalUrl={browser.final_url} redirects={redirects} />
          {screenshotUrl ? <ScreenshotPreview src={screenshotUrl} /> : null}
        </div>
      ) : null}

      {ai ? <AiAssessment assessment={ai} /> : null}

      {technicalAnalysis.length > 0 ? (
        <EvidenceList title="Technical Analyzers" items={technicalAnalysis} />
      ) : null}

      {reputation.length > 0 ? <EvidenceList title="Reputation" items={reputation} /> : null}

      {pendingCapabilities.length > 0 ? (
        <p className="text-xs font-medium uppercase text-zinc-500 dark:text-zinc-500">
          {pendingCapabilities.length} capability queued for later phases
        </p>
      ) : null}
    </div>
  );
}

function RetryButton({ onRetry }: { onRetry: () => void }) {
  return (
    <button
      className="mt-3 inline-flex min-h-10 items-center gap-2 rounded-lg border border-current px-3 py-2 text-sm font-semibold transition hover:bg-amber-100/70 dark:hover:bg-amber-900/30"
      onClick={onRetry}
      type="button"
    >
      <RotateCcw aria-hidden="true" size={16} />
      Retry scan
    </button>
  );
}

function RedirectTrail({
  finalUrl,
  redirects
}: {
  finalUrl: unknown;
  redirects: Array<Record<string, unknown>>;
}) {
  return (
    <div className="mt-4 border-t border-zinc-200 pt-4 dark:border-zinc-800">
      <h4 className="text-sm font-semibold tracking-normal">Redirect Trail</h4>
      {redirects.length > 0 ? (
        <ol className="mt-3 space-y-3">
          {redirects.map((redirect, index) => (
            <li
              className="border-l-2 border-zinc-200 pl-3 text-sm text-zinc-600 dark:border-zinc-700 dark:text-zinc-300"
              key={`${String(redirect.url)}-${index}`}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-zinc-800 dark:text-zinc-100">Step {index + 1}</span>
                <span className="rounded-md bg-zinc-100 px-2 py-1 text-xs font-semibold text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">
                  HTTP {formatUnknown(redirect.status_code)}
                </span>
              </div>
              <p className="mt-1 break-words">{formatUnknown(redirect.url)}</p>
              {redirect.location ? (
                <p className="mt-1 break-words text-zinc-500 dark:text-zinc-400">
                  Location: {formatUnknown(redirect.location)}
                </p>
              ) : null}
            </li>
          ))}
        </ol>
      ) : (
        <p className="mt-3 text-sm leading-6 text-zinc-600 dark:text-zinc-300">
          No HTTP redirects observed; the page loaded directly.
        </p>
      )}
      <p className="mt-3 break-words text-sm text-zinc-600 dark:text-zinc-300">
        Final destination: {formatUnknown(finalUrl)}
      </p>
    </div>
  );
}

function ScreenshotPreview({ src }: { src: string }) {
  const [failedToLoad, setFailedToLoad] = useState(false);

  return (
    <figure className="mt-4 border-t border-zinc-200 pt-4 dark:border-zinc-800">
      <figcaption className="text-sm font-semibold tracking-normal">Captured Screenshot</figcaption>
      {failedToLoad ? (
        <p className="mt-3 text-sm leading-6 text-zinc-600 dark:text-zinc-300">
          The captured screenshot is no longer available.
        </p>
      ) : (
        <img
          alt="Captured page screenshot"
          className="mt-3 max-h-[32rem] w-full rounded-lg border border-zinc-200 bg-slate-50 object-contain object-top dark:border-zinc-800 dark:bg-zinc-950"
          loading="lazy"
          onError={() => setFailedToLoad(true)}
          src={src}
        />
      )}
    </figure>
  );
}

function AiAssessment({ assessment }: { assessment: Record<string, unknown> }) {
  const weights = getRecordArray(assessment.evidence_weights);

  return (
    <div className="border-t border-zinc-200 pt-4 dark:border-zinc-800">
      <h3 className="text-sm font-semibold tracking-normal">AI Assessment</h3>
      <div className="mt-3 grid gap-2 text-sm text-zinc-600 dark:text-zinc-300 sm:grid-cols-2">
        <span>Provider: {formatUnknown(assessment.provider)}</span>
        <span>Model: {formatUnknown(assessment.model)}</span>
        <span>Status: {formatUnknown(assessment.status)}</span>
        <span>Fallback: {String(Boolean(assessment.fallback_used))}</span>
        <span>Confidence: {formatPercent(assessment.confidence)}</span>
        <span className="break-words">Action: {formatUnknown(assessment.recommended_action)}</span>
      </div>

      {weights.length > 0 ? (
        <div className="mt-4 space-y-2">
          {weights.slice(0, 4).map((weight) => (
            <div
              className="grid gap-1 text-sm text-zinc-600 dark:text-zinc-300 sm:grid-cols-[110px_1fr]"
              key={`${String(weight.source)}-${String(weight.reason)}`}
            >
              <span className="font-semibold text-zinc-700 dark:text-zinc-200">
                {formatUnknown(weight.source)} - {formatUnknown(weight.weight)}
              </span>
              <span>{formatUnknown(weight.reason)}</span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function EvidenceList({ items, title }: { items: Array<Record<string, unknown>>; title: string }) {
  return (
    <div className="border-t border-zinc-200 pt-4 dark:border-zinc-800">
      <h3 className="text-sm font-semibold tracking-normal">{title}</h3>
      <div className="mt-3 space-y-3">
        {items.map((item) => (
          <div className="border-l-2 border-zinc-200 pl-3 dark:border-zinc-700" key={String(item.source)}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">
                {formatUnknown(item.title)}
              </span>
              <span className="rounded-md bg-zinc-100 px-2 py-1 text-xs font-semibold uppercase text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400">
                {formatUnknown(item.severity)}
              </span>
            </div>
            <p className="mt-1 text-sm leading-6 text-zinc-600 dark:text-zinc-300">
              {formatUnknown(item.description)}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="mb-1 text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-500">
        {label}
      </dt>
      <dd className="break-words text-zinc-700 dark:text-zinc-200">{value}</dd>
    </div>
  );
}

function titleCase(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function formatDate(value: string | null) {
  if (!value) {
    return "Not complete";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

function getRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function getRecordArray(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is Record<string, unknown> => getRecord(item) !== null);
}

function formatUnknown(value: unknown) {
  if (value === null || value === undefined || value === "") {
    return "n/a";
  }
  return String(value);
}

function formatPercent(value: unknown) {
  if (typeof value !== "number") {
    return "n/a";
  }
  return `${Math.round(value * 100)}%`;
}

function formatBytes(value: unknown) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "n/a";
  }
  if (value < 1024) {
    return `${value} B`;
  }
  return `${Math.round((value / 1024) * 10) / 10} KB`;
}
