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
} from "@/components/ui/card";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";

export default function SignIn() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [step, setStep] = useState<"email" | "otp">("email");
  const [otpValue, setOtpValue] = useState("");

  async function handleEmailSubmit(e: FormEvent) {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await fetch("/api/auth/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to send OTP");
      }

      setStep("otp");
      toast.success("OTP Sent", {
        description: "Check your email for the verification code",
      });
    } catch (error) {
      toast.error("Error", {
        description: error instanceof Error ? error.message : "Failed to send OTP",
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function handleOtpSubmit(e: FormEvent) {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await fetch("/api/auth/otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          email, 
          otp: otpValue,
          storeVerification: true,
          verificationMethod: "otp",
          verificationTimestamp: new Date().toISOString()
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to verify OTP");
      }

      const userResponse = await fetch("/api/auth/user", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });

      if (!userResponse.ok) {
        const error = await userResponse.json();
        throw new Error(error.error || "Failed to get user info");
      }

      const { hasPassphrase } = await userResponse.json();

      if (!hasPassphrase) {
        router.push("/auth/passphrase/setup");
        return;
      }

      router.push("/");
    } catch (error) {
      toast.error("Error", {
        description: error instanceof Error ? error.message : "Failed to verify OTP",
      });
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="container flex items-center justify-center min-h-screen">
      <Card className="w-full max-w-md p-6 bg-surface-100 dark:bg-surface-800 border-surface-300 dark:border-surface-600">
        <CardHeader>
          <CardTitle>Sign In</CardTitle>
          <CardDescription>
            {step === "email"
              ? "Enter your email to receive a verification code"
              : "Enter the verification code sent to your email"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {step === "email" ? (
            <form onSubmit={handleEmailSubmit} className="flex flex-col gap-4">
              <Input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={cn(
                  "bg-surface-50 dark:bg-surface-900",
                  "border-surface-300 dark:border-surface-600",
                  "focus-visible:ring-1 focus-visible:ring-ring"
                )}
                required
              />
              <Button
                type="submit"
                variant="filled-primary"
                className="hover:variant-soft-primary dark:bg-primary-700"
                disabled={isLoading}
              >
                {isLoading ? "Loading..." : "Send Code"}
              </Button>
            </form>
          ) : (
            <form onSubmit={handleOtpSubmit} className="flex flex-col gap-4">
              <InputOTP
                value={otpValue}
                onChange={setOtpValue}
                maxLength={6}
                render={({ slots }) => (
                  <InputOTPGroup>
                    {slots.map((slot, i) => (
                      <InputOTPSlot
                        key={i}
                        {...slot}
                        index={i}
                        className={cn(
                          "bg-surface-50 dark:bg-surface-900",
                          "border-surface-300 dark:border-surface-600",
                          "focus-visible:ring-1 focus-visible:ring-ring"
                        )}
                      />
                    ))}
                  </InputOTPGroup>
                )}
              />
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="ghost-surface"
                  className="hover:variant-soft-surface dark:hover:bg-surface-700"
                  onClick={() => setStep("email")}
                  disabled={isLoading}
                >
                  Back
                </Button>
                <Button
                  type="submit"
                  variant="filled-primary"
                  className="hover:variant-soft-primary dark:bg-primary-700"
                  disabled={isLoading}
                >
                  {isLoading ? "Loading..." : "Verify"}
                </Button>
              </div>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
