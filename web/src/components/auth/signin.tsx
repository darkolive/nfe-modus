"use client";

import { useState, useRef, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { toBase64Url } from "@/lib/webauthn-browser";

export default function SignIn() {
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [step, setStep] = useState<"email" | "otp">("email");
  const dialogRef = useRef<HTMLDivElement>(null);

  const handleOpenChange = (open: boolean) => {
    setIsOpen(open);
    if (!open) {
      // Reset form state when dialog closes
      setStep("email");
      setEmail("");
      setOtp("");
    }
  };

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
      // Convert OTP to base64url format
      const base64OTP = toBase64Url(Buffer.from(otp).toString("base64"));

      const response = await fetch("/api/auth/otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          email, 
          otp: base64OTP,
          storeVerification: true,
          verificationMethod: "otp",
          verificationTimestamp: new Date().toISOString()
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to verify OTP");
      }

      // Check if user has passphrase set up
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
        // Redirect to passphrase setup
        window.location.href = "/auth/passphrase/setup";
        return;
      }

      // Redirect to home page
      window.location.href = "/";
    } catch (error) {
      toast.error("Error", {
        description: error instanceof Error ? error.message : "Failed to verify OTP",
      });
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={handleOpenChange}>
      <Button
        variant="ghost-surface"
        className="hover:variant-soft-surface dark:hover:bg-surface-700"
        onClick={() => handleOpenChange(true)}
      >
        Sign In
      </Button>
      <DialogContent
        ref={dialogRef}
        className={cn(
          "p-4 gap-4",
          "bg-surface-100 dark:bg-surface-800",
          "border-surface-300 dark:border-surface-600",
          "backdrop:bg-surface-900/50"
        )}
      >
        <DialogHeader>
          <DialogTitle>Sign In</DialogTitle>
          <DialogDescription>
            {step === "email"
              ? "Enter your email to receive a verification code"
              : "Enter the verification code sent to your email"}
          </DialogDescription>
        </DialogHeader>

        <form
          method="dialog"
          onSubmit={step === "email" ? handleEmailSubmit : handleOtpSubmit}
          className="flex flex-col gap-4"
        >
          {step === "email" ? (
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
          ) : (
            <div className="flex flex-col items-center gap-4">
              <InputOTP
                value={otp}
                onChange={setOtp}
                maxLength={6}
                disabled={isLoading}
              >
                <InputOTPGroup>
                  <InputOTPSlot index={0} />
                  <InputOTPSlot index={1} />
                  <InputOTPSlot index={2} />
                  <InputOTPSlot index={3} />
                  <InputOTPSlot index={4} />
                  <InputOTPSlot index={5} />
                </InputOTPGroup>
              </InputOTP>
              <p className="text-sm text-surface-500 dark:text-surface-400">
                Enter the 6-digit code sent to your email
              </p>
            </div>
          )}

          <DialogFooter>
            {step === "otp" && (
              <Button
                type="button"
                variant="ghost-surface"
                className="hover:variant-soft-surface dark:hover:bg-surface-700"
                onClick={() => setStep("email")}
                disabled={isLoading}
              >
                Back
              </Button>
            )}
            <Button
              type="submit"
              variant="filled-primary"
              className="hover:variant-soft-primary dark:bg-primary-700"
              disabled={isLoading || (step === "otp" && otp.length !== 6)}
            >
              {isLoading
                ? "Loading..."
                : step === "email"
                ? "Send Code"
                : "Verify"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
