import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '@/components/Header';
import { CheckCard } from '@/components/CheckCard';
import { ReportCard } from '@/components/ReportCard';
import { HistoryPanel } from '@/components/HistoryPanel';
import { useAuth } from '@/contexts/AuthContext';

export const DashboardPage = () => {
  const { user, isLoading } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isLoading && !user) {
      navigate('/');
    }
  }, [user, isLoading, navigate]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-muted-foreground">Loading...</p>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-muted/30">
      <div className="max-w-7xl mx-auto border-x min-h-screen bg-background">
        <Header />
        
        <main className="p-6 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <CheckCard />
            <ReportCard />
          </div>

          <HistoryPanel />
        </main>
      </div>
    </div>
  );
};
