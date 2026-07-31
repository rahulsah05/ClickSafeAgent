import { Moon, ShieldCheck, Sun } from "lucide-react";
import type { ReactNode } from "react";

interface ShellProps {
  children: ReactNode;
  onThemeChange: () => void;
  theme: "light" | "dark";
}

export function Shell({ children, onThemeChange, theme }: ShellProps) {
  const ThemeIcon = theme === "dark" ? Sun : Moon;

  return (
    <main className="min-h-screen bg-slate-50 px-4 py-5 text-zinc-950 transition-colors dark:bg-ink-950 dark:text-slate-50 sm:px-6 lg:px-8">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6">
        <header className="flex flex-col gap-4 border-b border-zinc-200 pb-5 dark:border-zinc-800 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-emerald-500 text-white shadow-soft">
              <ShieldCheck aria-hidden="true" size={24} />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-normal sm:text-3xl">ClickSafe</h1>
              <p className="text-sm font-medium text-zinc-500 dark:text-zinc-400">
                Phishing risk console
              </p>
            </div>
          </div>

          <button
            aria-label="Toggle dark mode"
            className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-zinc-200 bg-white text-zinc-700 shadow-sm transition hover:border-emerald-300 hover:text-emerald-700 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:border-emerald-500 dark:hover:text-emerald-300"
            onClick={onThemeChange}
            type="button"
          >
            <ThemeIcon aria-hidden="true" size={19} />
          </button>
        </header>

        {children}
      </div>
    </main>
  );
}

