import { useEffect, useState } from "react";

import { ResultPanel } from "./components/ResultPanel";
import { Shell } from "./components/Shell";
import { UrlScanner } from "./components/UrlScanner";
import { analyzeUrl } from "./lib/api";
import type { AnalysisResponse } from "./types/analysis";

type Theme = "light" | "dark";

function App() {
  const [theme, setTheme] = useState<Theme>("dark");
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);

  async function handleScan(url: string) {
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await analyzeUrl(url);
      setResult(response);
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Scan failed");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <Shell
      theme={theme}
      onThemeChange={() => setTheme((currentTheme) => (currentTheme === "dark" ? "light" : "dark"))}
    >
      <section className="grid gap-6 xl:grid-cols-[minmax(320px,0.95fr)_minmax(420px,1.35fr)]">
        <UrlScanner isLoading={isLoading} onScan={handleScan} />
        <ResultPanel error={error} isLoading={isLoading} result={result} />
      </section>
    </Shell>
  );
}

export default App;

