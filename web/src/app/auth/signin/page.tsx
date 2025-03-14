"use client";

import { useState, type FormEvent } from "react";
import { client } from "@passwordless-id/webauthn";
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
import { sendOtpEmail, verifyOtp } from "@/app/actions/auth";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { toast } from "sonner";
import { useRouter } from "next/navigation";

export default function SignIn() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [firstName, setFirstName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [step, setStep] = useState<
    "email" | "otp" | "auth-options" | "register-info"
  >("email");
  const [authTab, setAuthTab] = useState<"webauthn" | "passphrase">("webauthn");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [otpValue, setOtpValue] = useState("");
  const [isNewUser, setIsNewUser] = useState(false);
  const [marketingConsent, setMarketingConsent] = useState(false);
  // Add a user state to track authentication methods
  const [user, setUser] = useState<{
    exists: boolean;
    hasWebAuthn: boolean;
    hasPassphrase: boolean;
  } | null>(null);

  async function handleEmailSubmit(e: FormEvent) {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      // Check if user exists in the database
      const response = await fetch(
        `/api/auth/check-user?email=${encodeURIComponent(email)}`
      );
      const data = await response.json();

      setIsNewUser(!data.exists);
      setUser(data);

      // Send OTP for verification
      const otpResult = await sendOtpEmail(email);

      if (otpResult.success) {
        setStep("otp");
        setOtpValue("");
        toast.success("Verification code sent", {
          description: `We've sent a code to ${email}`,
        });
      } else {
        setError(otpResult.error || "Failed to send verification code");
        toast.error("Error", {
          description: otpResult.error || "Failed to send verification code",
        });
      }
    } catch (error) {
      console.error("Error:", error);
      setError("An error occurred. Please try again.");
      toast.error("Error", {
        description: "An unexpected error occurred",
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function handleOtpSubmit(e: FormEvent) {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      // Verify the OTP
      const result = await verifyOtp(email, otpValue);

      if (result.success) {
        // OTP verification successful
        if (isNewUser) {
          // New user - collect additional info
          setStep("register-info");
        } else {
          // Existing user - show auth options
          setStep("auth-options");
        }

        toast.success("Email verified", {
          description: "Your email has been successfully verified",
        });
      } else {
        setError(result.error || "Invalid verification code");
        toast.error("Error", {
          description: result.error || "Invalid verification code",
        });
      }
    } catch (error) {
      console.error("Error:", error);
      setError("An error occurred. Please try again.");
      toast.error("Error", {
        description: "An unexpected error occurred",
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function handleRegistrationInfoSubmit(e: FormEvent) {
    e.preventDefault();

    // Validate passphrase if using passphrase auth
    if (authTab === "passphrase") {
      if (passphrase.length < 8) {
        setError("Passphrase must be at least 8 characters");
        return;
      }

      if (passphrase !== confirmPassphrase) {
        setError("Passphrases do not match");
        return;
      }
    }

    // Proceed to authentication options
    setStep("auth-options");
  }

  async function handleWebAuthnRegistration() {
    setIsLoading(true);
    setError("");

    try {
      // Check if WebAuthn is supported
      if (!(await client.isAvailable())) {
        throw new Error("WebAuthn is not supported in this browser");
      }

      // Get registration options from the server
      const response = await fetch("/api/auth/webauthn/register-options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          name: firstName || email.split("@")[0],
        }),
      });

      const options = await response.json();

      if (options.error) {
        throw new Error(options.error);
      }

      // Start the registration process
      const result = await client.register(options);

      // Send the credential to the server
      const verificationResponse = await fetch(
        "/api/auth/webauthn/register-verify",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email,
            response: result,
            name: firstName || email.split("@")[0],
            marketingConsent,
          }),
        }
      );

      const verification = await verificationResponse.json();

      if (verification.error) {
        throw new Error(verification.error);
      }

      // Registration successful - user is now signed in
      toast.success("Registration successful", {
        description: "You have successfully registered and signed in",
      });

      // If the server indicates the user should set up a passphrase, redirect to that page
      if (verification.shouldSetupPassphrase) {
        router.push("/auth/setup-passphrase");
      } else {
        // Otherwise, redirect to home page or dashboard
        router.push("/");
      }
    } catch (error) {
      console.error("WebAuthn registration error:", error);
      setError(
        error instanceof Error
          ? error.message
          : "WebAuthn registration failed. Please try again."
      );
      toast.error("Error", {
        description:
          error instanceof Error
            ? error.message
            : "WebAuthn registration failed. Please try again.",
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function handleWebAuthnLogin() {
    setIsLoading(true);
    setError("");

    try {
      // Check if WebAuthn is supported
      if (!(await client.isAvailable())) {
        throw new Error("WebAuthn is not supported in this browser");
      }

      // Get authentication options from the server
      const response = await fetch("/api/auth/webauthn/login-options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const options = await response.json();

      if (options.error) {
        throw new Error(options.error);
      }

      // Start the authentication process
      const result = await client.authenticate(options);

      // Verify the authentication with the server
      const verificationResponse = await fetch(
        "/api/auth/webauthn/login-verify",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email,
            response: result,
          }),
        }
      );

      const verification = await verificationResponse.json();

      if (verification.error) {
        throw new Error(verification.error);
      }

      // Redirect to dashboard or home page
      toast.success("Success", {
        description: "You have successfully signed in",
      });

      router.push("/");
    } catch (error) {
      console.error("WebAuthn login error:", error);
      setError(
        error instanceof Error
          ? error.message
          : "WebAuthn login failed. Please try again."
      );
      toast.error("Error", {
        description:
          error instanceof Error
            ? error.message
            : "WebAuthn login failed. Please try again.",
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function handlePassphraseRegistration() {
    setIsLoading(true);
    setError("");

    try {
      // Register with passphrase
      const response = await fetch("/api/auth/passphrase/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          passphrase,
          name: firstName || email.split("@")[0],
          marketingConsent,
        }),
      });

      const result = await response.json();

      if (result.error) {
        throw new Error(result.error);
      }

      // Registration successful - user is now signed in
      // No need to call handlePassphraseLogin() as the server already created a session
      toast.success("Success", {
        description: "You have successfully registered and signed in",
      });

      // Redirect to home page or dashboard
      router.push("/");
    } catch (error) {
      console.error("Passphrase registration error:", error);
      setError(
        error instanceof Error
          ? error.message
          : "Registration failed. Please try again."
      );
      toast.error("Error", {
        description:
          error instanceof Error
            ? error.message
            : "Registration failed. Please try again.",
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function handlePassphraseLogin() {
    setIsLoading(true);
    setError("");

    try {
      // Sign in with passphrase
      const response = await fetch("/api/auth/passphrase/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          passphrase,
        }),
      });

      const result = await response.json();

      if (result.error) {
        // Special handling for the "no passphrase" case
        if (response.status === 400) {
          if (result.error.includes("does not have a passphrase")) {
            setError(
              "You haven't set up a passphrase yet. Please use passkey login or set up a passphrase first."
            );
            toast.error("No passphrase set up", {
              description:
                "You need to set up a passphrase before you can use this login method",
              action: {
                label: "Set up now",
                onClick: () => {
                  // If the user is already authenticated with WebAuthn, we can redirect them to setup
                  if (user?.hasWebAuthn) {
                    router.push("/auth/setup-passphrase");
                  } else {
                    // Otherwise, guide them to use WebAuthn first
                    setAuthTab("webauthn");
                  }
                },
              },
            });
            return;
          } else if (result.needsReset) {
            setError(
              "Your password needs to be reset. Please use another authentication method or reset your password."
            );
            toast.error("Password reset needed", {
              description: "Your password data is missing or corrupted",
              action: {
                label: "Use passkey instead",
                onClick: () => {
                  setAuthTab("webauthn");
                },
              },
            });
            return;
          }
        }

        throw new Error(result.error);
      }

      // Redirect to dashboard or home page
      toast.success("Success", {
        description: "You have successfully signed in",
      });

      router.push("/");
    } catch (error) {
      console.error("Passphrase login error:", error);
      setError(
        error instanceof Error
          ? error.message
          : "Login failed. Please try again."
      );
      toast.error("Error", {
        description:
          error instanceof Error
            ? error.message
            : "Login failed. Please try again.",
      });
    } finally {
      setIsLoading(false);
    }
  }

  function handleOtpChange(value: string) {
    setOtpValue(value);
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>
            {step === "email" && "Sign In"}
            {step === "otp" && "Verify Email"}
            {step === "register-info" && "Complete Registration"}
            {step === "auth-options" && (isNewUser ? "Register" : "Sign In")}
          </CardTitle>
          <CardDescription>
            {step === "email" &&
              "Enter your email to sign in or create an account"}
            {step === "otp" && "Enter the verification code sent to your email"}
            {step === "register-info" &&
              "Please provide some additional information"}
            {step === "auth-options" &&
              (isNewUser
                ? "Choose how you want to secure your account"
                : "Choose how you want to sign in")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {step === "email" && (
            <form onSubmit={handleEmailSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="name@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              {error && <p className="text-sm text-red-500">{error}</p>}
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? "Sending code..." : "Continue with Email"}
              </Button>
            </form>
          )}

          {step === "otp" && (
            <form onSubmit={handleOtpSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="otp">Verification Code</Label>
                <div className="flex justify-center">
                  <InputOTP
                    maxLength={6}
                    value={otpValue}
                    onChange={handleOtpChange}
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
                </div>
              </div>
              {error && <p className="text-sm text-red-500">{error}</p>}
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? "Verifying..." : "Verify Code"}
              </Button>
              <div className="flex justify-between items-center text-sm">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="gap-1"
                  onClick={() => setStep("email")}
                >
                  Back
                </Button>
                <Button
                  type="button"
                  variant="link"
                  className="px-0"
                  onClick={async () => {
                    setIsLoading(true);
                    const result = await sendOtpEmail(email);
                    setIsLoading(false);

                    if (result.success) {
                      setOtpValue("");
                      toast.success("Code resent", {
                        description:
                          "A new verification code has been sent to your email",
                      });
                    } else {
                      toast.error("Error", {
                        description: result.error || "Failed to resend code",
                      });
                    }
                  }}
                  disabled={isLoading}
                >
                  Resend code
                </Button>
              </div>
            </form>
          )}

          {step === "register-info" && (
            <form onSubmit={handleRegistrationInfoSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="firstName">First Name</Label>
                <Input
                  id="firstName"
                  type="text"
                  placeholder="Your first name"
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                />
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="marketingConsent"
                  checked={marketingConsent}
                  onCheckedChange={(checked) =>
                    setMarketingConsent(checked === true)
                  }
                />
                <Label htmlFor="marketingConsent" className="text-sm">
                  I agree to receive marketing emails (optional)
                </Label>
              </div>

              {error && <p className="text-sm text-red-500">{error}</p>}

              <Button type="submit" className="w-full">
                Continue
              </Button>
              <Button
                type="button"
                variant="outline"
                className="w-full"
                onClick={() => setStep("otp")}
              >
                Back
              </Button>
            </form>
          )}

          {step === "auth-options" && (
            <Tabs
              defaultValue="webauthn"
              onValueChange={(value) =>
                setAuthTab(value as "webauthn" | "passphrase")
              }
              className="space-y-4"
            >
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="webauthn">Passkey</TabsTrigger>
                <TabsTrigger value="passphrase">Passphrase</TabsTrigger>
              </TabsList>

              <TabsContent value="webauthn" className="space-y-4">
                <div className="space-y-2">
                  <p className="text-sm">
                    {isNewUser
                      ? "Register with a passkey for passwordless authentication. This uses your device's biometrics or security features."
                      : "Sign in with your passkey."}
                  </p>
                  {error && <p className="text-sm text-red-500">{error}</p>}
                  <Button
                    onClick={
                      isNewUser
                        ? handleWebAuthnRegistration
                        : handleWebAuthnLogin
                    }
                    className="w-full"
                    disabled={isLoading}
                  >
                    {isLoading
                      ? isNewUser
                        ? "Registering..."
                        : "Signing in..."
                      : isNewUser
                        ? "Register with Passkey"
                        : "Sign in with Passkey"}
                  </Button>
                </div>
              </TabsContent>

              <TabsContent value="passphrase" className="space-y-4">
                {isNewUser ? (
                  <div className="space-y-2">
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
                      <Label htmlFor="confirmPassphrase">
                        Confirm Passphrase
                      </Label>
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
                    <Button
                      onClick={handlePassphraseRegistration}
                      className="w-full"
                      disabled={isLoading}
                    >
                      {isLoading
                        ? "Registering..."
                        : "Register with Passphrase"}
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {user && !user.hasPassphrase && (
                      <div className="bg-yellow-50 p-3 rounded-md mb-3">
                        <p className="text-sm text-yellow-800">
                          You haven&apos;t set up a passphrase yet. Please use
                          passkey login or set up a passphrase first.
                        </p>
                        <Button
                          variant="outline"
                          size="sm"
                          className="mt-2"
                          onClick={() => setAuthTab("webauthn")}
                        >
                          Use Passkey Instead
                        </Button>
                      </div>
                    )}
                    <div className="space-y-2">
                      <Label htmlFor="passphrase">Passphrase</Label>
                      <Input
                        id="passphrase"
                        type="password"
                        placeholder="Enter your passphrase"
                        value={passphrase}
                        onChange={(e) => setPassphrase(e.target.value)}
                        required
                      />
                    </div>
                    {error && <p className="text-sm text-red-500">{error}</p>}
                    <Button
                      onClick={handlePassphraseLogin}
                      className="w-full"
                      disabled={
                        isLoading || (user ? !user.hasPassphrase : false)
                      }
                    >
                      {isLoading ? "Signing in..." : "Sign in with Passphrase"}
                    </Button>
                  </div>
                )}
              </TabsContent>

              <Button
                type="button"
                variant="outline"
                className="w-full mt-2"
                onClick={() =>
                  isNewUser ? setStep("register-info") : setStep("email")
                }
              >
                Back
              </Button>
            </Tabs>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
