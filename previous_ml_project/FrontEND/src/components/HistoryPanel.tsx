import { useState, useEffect } from 'react';
import { History, Trash2, AlertCircle, CheckCircle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { getHistory, clearHistory } from '@/services/api';
import { HistoryItem } from '@/types';

export const HistoryPanel = () => {
  const [history, setHistory] = useState<HistoryItem[]>([]);

  const loadHistory = () => {
    setHistory(getHistory());
  };

  useEffect(() => {
    loadHistory();

    // Listen for history updates
    const handleStorageChange = () => {
      loadHistory();
    };

    window.addEventListener('storage', handleStorageChange);
    
    // Custom event for same-page updates
    const handleHistoryUpdate = () => {
      loadHistory();
    };
    window.addEventListener('historyUpdated', handleHistoryUpdate);

    return () => {
      window.removeEventListener('storage', handleStorageChange);
      window.removeEventListener('historyUpdated', handleHistoryUpdate);
    };
  }, []);

  const handleClearHistory = () => {
    clearHistory();
    setHistory([]);
  };

  const formatTimestamp = (timestamp: number) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  if (history.length === 0) {
    return null;
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <History className="h-5 w-5" aria-hidden="true" />
              Scan History
            </CardTitle>
            <CardDescription>
              Your recent URL checks ({history.length} {history.length === 1 ? 'scan' : 'scans'})
            </CardDescription>
          </div>
          <Button 
            variant="outline" 
            size="sm"
            onClick={handleClearHistory}
            className="flex items-center gap-2"
            aria-label="Clear all history"
          >
            <Trash2 className="h-4 w-4" aria-hidden="true" />
            Clear
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {history.map((item) => (
            <div 
              key={item.id}
              className="flex items-start gap-3 p-3 rounded-md border bg-card hover:bg-accent/50 transition-colors"
            >
              {item.label === 'scam' ? (
                <AlertCircle className="h-5 w-5 text-destructive flex-shrink-0 mt-0.5" aria-label="Scam" />
              ) : (
                <CheckCircle className="h-5 w-5 text-success flex-shrink-0 mt-0.5" aria-label="Safe" />
              )}
              
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{item.url}</p>
                <div className="flex items-center gap-2 mt-1">
                  <Badge 
                    variant={item.label === 'scam' ? 'destructive' : 'default'}
                    className={item.label === 'safe' ? 'bg-success hover:bg-success/90' : ''}
                  >
                    {item.label.toUpperCase()}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {Math.round(item.confidence * 100)}% confidence
                  </span>
                  <span className="text-xs text-muted-foreground">
                    • {formatTimestamp(item.timestamp)}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
