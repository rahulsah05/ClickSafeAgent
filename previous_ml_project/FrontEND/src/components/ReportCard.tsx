import { useState } from 'react';
import { Flag } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { report } from '@/services/api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';

export const ReportCard = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const { user } = useAuth();
  const { toast } = useToast();

  const handleReport = async () => {
    if (!url.trim()) {
      toast({
        title: "URL Required",
        description: "Please enter a URL to report",
        variant: "destructive",
      });
      return;
    }

    // removed strict validator
    // accept any type of URL including http, https and plain domains
    setUrl(url.trim());

    setLoading(true);

    try {
      await report({
        url,
        reporter: user?.mobile || 'anonymous',
      });

      toast({
        title: "Report Submitted",
        description: "Thank you for helping keep the internet safe!",
      });

      setUrl('');
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to submit report. Please try again.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleReport();
    }
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Flag className="h-5 w-5" aria-hidden="true" />
          Report URL
        </CardTitle>
        <CardDescription>
          Report a suspicious or malicious URL to help protect others
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="p-6 border rounded-md bg-muted/30">
          <Input
            type="url"
            placeholder="https://suspicious-site.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyPress={handleKeyPress}
            disabled={loading}
            className="mb-4"
            aria-label="URL to report"
          />
          <Button 
            onClick={handleReport}
            disabled={loading}
            variant="destructive"
            className="w-full"
            aria-busy={loading}
          >
            {loading ? 'Reporting...' : 'report'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};
