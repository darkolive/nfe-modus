"use client";

import { useState, useEffect, FormEvent, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

// Wrap component that uses useSearchParams in Suspense
function ResetPassphraseContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token");

  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [isValidToken, setIsValidToken] = useState(false);
  const [tokenChecked, setTokenChecked] = useState(false);

  useEffect(() => {
    // Validate token on page load
    async function validateToken() {
      if (!token) {
        setError("Invalid or missing reset token");
        setTokenChecked(true);
        return;
      }

      try {
        const response = await fetch(`/api/auth/passphrase/validate-reset-token?token=${token}`);
        const data = await response.json();

        if (response.ok && data.valid) {
          setIsValidToken(true);
        } else {
          setError(data.error || "Invalid or expired reset token");
        }
      } catch (error) {
        console.error("Error validating token:", error);
        setError("Failed to validate reset token");
      } finally {
        setTokenChecked(true);
      }
    }

    validateToken();
  }, [token]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    
    // Validate input
    if (passphrase.length < 8) {
      setError("Passphrase must be at least 8 characters");
      return;
    }

    if (passphrase !== confirmPassphrase) {
      setError("Passphrases do not match");
      return;
    }

    setIsLoading(true);
    setError("");

    try {
      const response = await fetch("/api/auth/passphrase/reset", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          token,
          passphrase,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to reset passphrase");
      }

      toast.success("Passphrase reset successful", {
        description: "Your passphrase has been updated successfully",
      });

      // Directly redirect to home page since the session token is already set by the API
      router.push("/");
    } catch (error) {
      console.error("Error resetting passphrase:", error);
      setError(error instanceof Error ? error.message : "Failed to reset passphrase");
      toast.error("Error", {
        description: error instanceof Error ? error.message : "Failed to reset passphrase",
      });
    } finally {
      setIsLoading(false);
    }
  }

  if (!tokenChecked) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Reset Passphrase</CardTitle>
            <CardDescription>Validating your reset link...</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Reset Passphrase</CardTitle>
          <CardDescription>
            {isValidToken
              ? "Enter a new passphrase for your account"
              : "Invalid or expired reset link"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isValidToken ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="passphrase">New Passphrase</Label>
                <Input
                  id="passphrase"
                  type="password"
                  placeholder="Enter a secure passphrase"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  required
                  disabled={isLoading}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirmPassphrase">Confirm Passphrase</Label>
                <Input
                  id="confirmPassphrase"
                  type="password"
                  placeholder="Confirm your passphrase"
                  value={confirmPassphrase}
                  onChange={(e) => setConfirmPassphrase(e.target.value)}
                  required
                  disabled={isLoading}
                />
              </div>
              {error && <p className="text-sm text-red-500">{error}</p>}
              <Button
                type="submit"
                className="w-full"
                disabled={isLoading}
              >
                {isLoading ? "Resetting..." : "Reset Passphrase"}
              </Button>
            </form>
          ) : (
            <div className="text-center">
              <p className="text-red-500 mb-4">{error}</p>
              <Button
                onClick={() => router.push("/auth/signin")}
                className="w-full"
              >
                Back to Sign In
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// Main component with Suspense boundary
export default function ResetPassphrase() {
  return (
    <Suspense fallback={<div className="flex justify-center items-center min-h-screen">Loading...</div>}>
      <ResetPassphraseContent />
    </Suspense>
  );
}
