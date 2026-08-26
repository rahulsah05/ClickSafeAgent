import { Loader2, Search, ShieldAlert } from "lucide-react";
import { FormEvent, useState } from "react";

interface UrlScannerProps {
  isLoading: boolean;
  onScan: (url: string) => Promise<void>;
}

export function UrlScanner({ isLoading, onScan }: UrlScannerProps) {
  const [url, setUrl] = useState("");

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onScan(url.trim());
  }

  return (
    <section className="rounded-lg border border-zinc-200 bg-white p-5 shadow-soft dark:border-zinc-800 dark:bg-zinc-900">
      <div className="mb-5 flex items-start gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300">
          <ShieldAlert aria-hidden="true" size={21} />
        </div>
        <div>
          <h2 className="text-lg font-semibold tracking-normal">URL Scan</h2>
          <p className="mt-1 text-sm leading-6 text-zinc-500 dark:text-zinc-400">
            Submit a destination before opening it.
          </p>
        </div>
      </div>

      <form className="flex flex-col gap-3" onSubmit={handleSubmit}>
        <label className="text-sm font-medium text-zinc-700 dark:text-zinc-200" htmlFor="url">
          URL
        </label>
        <input
          autoCapitalize="none"
          className="min-h-12 rounded-lg border border-zinc-200 bg-slate-50 px-4 text-base text-zinc-950 outline-none transition placeholder:text-zinc-400 focus:border-emerald-500 focus:bg-white focus:ring-4 focus:ring-emerald-500/15 dark:border-zinc-800 dark:bg-zinc-950 dark:text-slate-50 dark:focus:bg-zinc-950"
          id="url"
          inputMode="url"
          onChange={(event) => setUrl(event.target.value)}
          placeholder="https://example.com"
          required
          spellCheck={false}
          type="text"
          value={url}
        />
        <button
          className="inline-flex min-h-12 items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:bg-zinc-400 dark:bg-emerald-500 dark:text-zinc-950 dark:hover:bg-emerald-400"
          disabled={isLoading}
          type="submit"
        >
          {isLoading ? (
            <Loader2 aria-hidden="true" className="animate-spin" size={18} />
          ) : (
            <Search aria-hidden="true" size={18} />
          )}
          {isLoading ? "Scanning" : "Analyze URL"}
        </button>
      </form>
    </section>
  );
}

