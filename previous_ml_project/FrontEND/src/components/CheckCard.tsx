import { useState } from 'react';
import { Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { predict } from '@/services/api';
import { saveToHistory } from '@/services/api';
import { PredictResponse } from '@/types';
import { ResultModal } from './ResultModal';
import { isValidUrl } from '@/lib/validators';
import { useToast } from '@/hooks/use-toast';

export const CheckCard = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PredictResponse | null>(null);
  const [showModal, setShowModal] = useState(false);
  const { toast } = useToast();
  const [lastCheckTime, setLastCheckTime] = useState(0);

  const handleCheck = async () => {
    // Rate limiting: prevent requests within 3 seconds
    const now = Date.now();
    if (now - lastCheckTime < 3000) {
      toast({
        title: "Please wait",
        description: "You can only check once every 3 seconds",
        variant: "destructive",
      });
      return;
    }

    if (!url.trim()) {
      toast({
        title: "URL Required",
        description: "Please enter a URL to check",
        variant: "destructive",
      });
      return;
    }

    if (!isValidUrl(url)) {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid URL (e.g., https://example.com)",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    setLastCheckTime(now);

    try {
      const response = await predict(url);
      setResult(response);
      setShowModal(true);

      // Save to history
      saveToHistory({
        id: `scan_${Date.now()}`,
        url: response.url,
        label: response.label,
        confidence: response.confidence,
        timestamp: Date.now(),
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to check URL. Please try again.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleCheck();
    }
  };

  return (
    <>
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" aria-hidden="true" />
            Check URL
          </CardTitle>
          <CardDescription>
            Enter a URL to check if it's safe or potentially dangerous
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="p-6 border rounded-md bg-muted/30">
            <Input
              type="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={loading}
              className="mb-4"
              aria-label="URL to check"
            />
            <Button 
              onClick={handleCheck}
              disabled={loading}
              className="w-full"
              aria-busy={loading}
            >
              {loading ? 'Checking...' : 'check'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {result && (
        <ResultModal
          result={result}
          open={showModal}
          onClose={() => setShowModal(false)}
        />
      )}
    </>
  );
};
