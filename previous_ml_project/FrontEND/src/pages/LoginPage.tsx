import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/contexts/AuthContext';
import { isValidName, isValidIndianMobile } from '@/lib/validators';
import { useToast } from '@/hooks/use-toast';

export const LoginPage = () => {
  const [name, setName] = useState('');
  const [mobile, setMobile] = useState('');
  const [errors, setErrors] = useState<{ name?: string; mobile?: string }>({});
  const navigate = useNavigate();
  const { login } = useAuth();
  const { toast } = useToast();

  const validate = (): boolean => {
    const newErrors: { name?: string; mobile?: string } = {};

    if (!isValidName(name)) {
      newErrors.name = 'Name is required and must be less than 100 characters';
    }

    if (!isValidIndianMobile(mobile)) {
      newErrors.mobile = 'Please enter a valid 10-digit Indian mobile number starting with 6-9';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!validate()) {
      return;
    }

    // Store user and redirect
    login({ name: name.trim(), mobile });
    
    toast({
      title: "Welcome!",
      description: `Logged in as ${name.trim()}`,
    });

    navigate('/dashboard');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-muted/30 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-4">
            <div className="p-3 rounded-full bg-primary/10">
              <Shield className="h-8 w-8 text-primary" aria-hidden="true" />
            </div>
          </div>
          <CardTitle className="text-2xl font-bold">ClickSafe</CardTitle>
          <CardDescription>
            Protect yourself from phishing and scam websites
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                type="text"
                placeholder="Enter your name"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  if (errors.name) setErrors({ ...errors, name: undefined });
                }}
                aria-invalid={!!errors.name}
                aria-describedby={errors.name ? "name-error" : undefined}
              />
              {errors.name && (
                <p id="name-error" className="text-sm text-destructive" role="alert">
                  {errors.name}
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="mobile">Mobile Number</Label>
              <Input
                id="mobile"
                type="tel"
                placeholder="10-digit mobile number"
                value={mobile}
                onChange={(e) => {
                  // Only allow digits
                  const value = e.target.value.replace(/\D/g, '');
                  setMobile(value.slice(0, 10));
                  if (errors.mobile) setErrors({ ...errors, mobile: undefined });
                }}
                maxLength={10}
                aria-invalid={!!errors.mobile}
                aria-describedby={errors.mobile ? "mobile-error" : undefined}
              />
              {errors.mobile && (
                <p id="mobile-error" className="text-sm text-destructive" role="alert">
                  {errors.mobile}
                </p>
              )}
              <p className="text-xs text-muted-foreground">
                Enter your 10-digit Indian mobile number
              </p>
            </div>

            <Button type="submit" className="w-full">
              Login
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};
