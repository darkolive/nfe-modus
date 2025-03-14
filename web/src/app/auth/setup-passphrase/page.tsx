"use client";

import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { useRouter } from "next/navigation";

export default function SetupPassphrase() {
  const router = useRouter();
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    // Validate passphrase
    if (passphrase.length < 8) {
      setError("Passphrase must be at least 8 characters");
      setIsLoading(false);
      return;
    }

    if (passphrase !== confirmPassphrase) {
      setError("Passphrases do not match");
      setIsLoading(false);
      return;
    }

    try {
      // Send request to set up passphrase
      const response = await fetch("/api/auth/passphrase/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ passphrase }),
      });

      const data = await response.json();

      if (data.error) {
        throw new Error(data.error);
      }

      toast.success("Passphrase set up successfully", {
        description:
          "You can now use your passphrase to sign in from any device",
      });

      // Redirect to dashboard or home
      router.push("/");
    } catch (error) {
      console.error("Error setting up passphrase:", error);
      setError(
        error instanceof Error ? error.message : "Failed to set up passphrase"
      );
      toast.error("Error", {
        description:
          error instanceof Error
            ? error.message
            : "Failed to set up passphrase",
      });
    } finally {
      setIsLoading(false);
    }
  }

  function handleSkip() {
    toast.info("Passphrase setup skipped", {
      description: "You can set up a passphrase later in your account settings",
    });
    router.push("/");
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Set Up Passphrase</CardTitle>
          <CardDescription>
            Setting up a passphrase allows you to sign in from devices that
            don&apos;t support passkeys.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="passphrase">Passphrase</Label>
              <Input
                id="passphrase"
                type="password"
                placeholder="Enter a secure passphrase"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                required
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
              />
            </div>
            {error && <p className="text-sm text-red-500">{error}</p>}
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? "Setting up..." : "Set Up Passphrase"}
            </Button>
          </form>
        </CardContent>
        <CardFooter>
          <Button variant="ghost" onClick={handleSkip} className="w-full">
            Skip for now
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
