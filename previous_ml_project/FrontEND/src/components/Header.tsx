import { User, LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';

export const Header = () => {
  const { user, logout } = useAuth();

  return (
    <header className="h-14 border-b bg-card flex items-center justify-between px-6">
      <div className="flex items-center gap-2 text-sm">
        <User className="h-4 w-4" aria-hidden="true" />
        <span className="font-medium">{user?.name || 'profile'}</span>
      </div>
      
      <h1 className="text-lg font-bold absolute left-1/2 -translate-x-1/2">
        ClickSafe
      </h1>
      
      <Button 
        variant="ghost" 
        size="sm"
        onClick={logout}
        className="flex items-center gap-2"
        aria-label="Logout"
      >
        <LogOut className="h-4 w-4" aria-hidden="true" />
        <span>logout</span>
      </Button>
    </header>
  );
};
