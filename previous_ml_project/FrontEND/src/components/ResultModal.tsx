import { AlertCircle, CheckCircle, Flag } from 'lucide-react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { PredictResponse } from '@/types';
import { report } from '@/services/api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { useState } from 'react';

interface ResultModalProps {
  result: PredictResponse;
  open: boolean;
  onClose: () => void;
}

export const ResultModal = ({ result, open, onClose }: ResultModalProps) => {
  const { user } = useAuth();
  const { toast } = useToast();
  const [reporting, setReporting] = useState(false);

  const isScam = result.label === 'scam';
  const confidencePercent = Math.round(result.confidence * 100);

  const handleReportFalsePositive = async () => {
    setReporting(true);
    try {
      await report({
        url: result.url,
        reporter: user?.mobile || 'anonymous',
        notes: `False positive report - was marked as ${result.label}`,
      });

      toast({
        title: "Report Submitted",
        description: "Thank you for your feedback!",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to submit report. Please try again.",
        variant: "destructive",
      });
    } finally {
      setReporting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent 
        className="sm:max-w-md"
        aria-describedby="result-description"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {isScam ? (
              <AlertCircle className="h-5 w-5 text-destructive" aria-hidden="true" />
            ) : (
              <CheckCircle className="h-5 w-5 text-success" aria-hidden="true" />
            )}
            <span className={isScam ? 'text-destructive' : 'text-success'}>
              {isScam ? 'SCAM DETECTED' : 'SAFE'}
            </span>
          </DialogTitle>
          <DialogDescription id="result-description">
            Analysis result for the submitted URL
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* URL */}
          <div>
            <p className="text-sm font-medium mb-1">URL:</p>
            <p className="text-sm text-muted-foreground break-all">{result.url}</p>
          </div>

          {/* Confidence */}
          <div>
            <p className="text-sm font-medium mb-2">Confidence:</p>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all ${isScam ? 'bg-destructive' : 'bg-success'}`}
                  style={{ width: `${confidencePercent}%` }}
                  role="progressbar"
                  aria-valuenow={confidencePercent}
                  aria-valuemin={0}
                  aria-valuemax={100}
                />
              </div>
              <span className="text-sm font-semibold">{confidencePercent}%</span>
            </div>
          </div>

          {/* Matched Rules */}
          {result.rules.length > 0 && (
            <div>
              <p className="text-sm font-medium mb-2">Matched Rules:</p>
              <div className="flex flex-wrap gap-1.5">
                {result.rules.map((rule) => (
                  <Badge key={rule} variant="secondary" className="text-xs">
                    {rule.replace(/_/g, ' ')}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Explanation */}
          <div>
            <p className="text-sm font-medium mb-2">Details:</p>
            <ul className="space-y-1 list-disc list-inside text-sm text-muted-foreground">
              {result.explanation.map((point, idx) => (
                <li key={idx}>{point}</li>
              ))}
            </ul>
          </div>

          {/* Actions */}
          <div className="flex gap-2 pt-2">
            <Button 
              variant="outline" 
              size="sm" 
              className="flex-1"
              onClick={onClose}
            >
              Close
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              onClick={handleReportFalsePositive}
              disabled={reporting}
              className="flex items-center gap-1.5"
            >
              <Flag className="h-3.5 w-3.5" aria-hidden="true" />
              {reporting ? 'Reporting...' : 'Report false positive'}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};
