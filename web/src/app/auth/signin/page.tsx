"use client";

import { useState, type FormEvent, useEffect } from "react";
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
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";

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
  const [webAuthnSupported, setWebAuthnSupported] = useState(true);

  // Check if WebAuthn is supported when component mounts
  useEffect(() => {
    // Check for WebAuthn support
    const isWebAuthnSupported = 
      typeof window !== 'undefined' && 
      window.PublicKeyCredential !== undefined;
    
    setWebAuthnSupported(isWebAuthnSupported);
    
    // If WebAuthn is not supported, default to passphrase
    if (!isWebAuthnSupported) {
      setAuthTab("passphrase");
    }
  }, []);

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
      if (!window.PublicKeyCredential) {
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
      const result = await startRegistration(options);

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
      toast.success("Success", {
        description: "Passkey set up successfully! Setting up a backup passphrase is required.",
      });
      
      setIsLoading(false);
      router.push("/auth/setup-passphrase");
      return;
    } catch (error) {
      console.error("Error during WebAuthn registration:", error);
      setError(error instanceof Error ? error.message : "Registration failed");
      toast.error("Registration failed", {
        description:
          error instanceof Error ? error.message : "Unknown error occurred",
      });
      setIsLoading(false);
    }
  }

  async function handleAddWebAuthnCredential() {
    setIsLoading(true);
    setError("");

    try {
      // Check if WebAuthn is supported
      if (!window.PublicKeyCredential) {
        throw new Error("WebAuthn is not supported in this browser");
      }

      // Get add credential options from the server
      const response = await fetch("/api/auth/webauthn/add-credential", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include", // Include cookies (for session token)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to get registration options");
      }

      const options = await response.json();

      // Start the registration process
      const result = await startRegistration(options);

      // Send the credential to the server
      const verificationResponse = await fetch(
        "/api/auth/webauthn/add-credential-verify",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include", // Include cookies (for session token)
          body: JSON.stringify({
            email,
            response: result,
            deviceName: "Browser Key",
            deviceInfo: navigator.userAgent || "Unknown Browser",
          }),
        }
      );

      if (!verificationResponse.ok) {
        const errorData = await verificationResponse.json();
        throw new Error(errorData.error || "Failed to verify credential");
      }

      const verification = await verificationResponse.json();

      if (verification.success) {
        toast.success("Passkey added successfully", {
          description: "You can now sign in using your passkey",
        });
        
        // Login with the new credential
        handleWebAuthnLogin();
      } else {
        throw new Error("Failed to add passkey");
      }
    } catch (error) {
      console.error("Error adding WebAuthn credential:", error);
      setError(error instanceof Error ? error.message : "Failed to add passkey");
      toast.error("Failed to add passkey", {
        description:
          error instanceof Error ? error.message : "Unknown error occurred",
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
      if (!window.PublicKeyCredential) {
        throw new Error("WebAuthn is not supported in this browser");
      }

      // Get authentication options from the server
      const response = await fetch("/api/auth/webauthn/login-options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const options = await response.json();

      // Check if this is a registration flow (user doesn't have credentials)
      if (options.isRegistrationFlow) {
        // This is actually a registration flow
        try {
          // Start the registration process
          const registrationResult = await startRegistration(options);
          
          // Verify the registration with the server
          const verificationResponse = await fetch(
            "/api/auth/webauthn/register-verify",
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                email,
                response: registrationResult,
                name: firstName || email.split("@")[0],
              }),
            }
          );

          const verification = await verificationResponse.json();

          if (verification.error) {
            throw new Error(verification.error);
          }

          // Registration successful - user is now signed in
          toast.success("Success", {
            description: "Passkey set up successfully! You're now signed in.",
          });
          
          setIsLoading(false);
          router.push("/dashboard");
          return;
        } catch (regError) {
          console.error("Error during WebAuthn registration:", regError);
          setError(regError instanceof Error ? regError.message : "Registration failed");
          
          // Fall back to passphrase login
          setAuthTab("passphrase");
          setIsLoading(false);
          return;
        }
      }

      if (options.error) {
        if (options.error === "No security keys found" && options.canRegisterWebAuthn) {
          setError("");
          setAuthTab("passphrase");
          setIsLoading(false);
          toast.info("No passkey found", {
            description: "You don't have a passkey set up yet. Please log in with your passphrase first.",
            duration: 5000,
          });
          return;
        }
        throw new Error(options.error);
      }

      // Start the authentication process
      const result = await startAuthentication(options);

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
        (error as Error).message || "WebAuthn login failed. Please try again."
      );
      toast.error("Error", {
        description:
          (error as Error).message ||
          "WebAuthn login failed. Please try again.",
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
        (error as Error).message || "Registration failed. Please try again."
      );
      toast.error("Error", {
        description:
          (error as Error).message || "Registration failed. Please try again.",
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function handlePassphraseLogin() {
    // Prevent submission if passphrase is empty
    if (!passphrase) {
      setError("Passphrase is required");
      return;
    }

    // Clear any previous errors
    setError("");
    setIsLoading(true);

    try {
      const response = await fetch("/api/auth/passphrase/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, passphrase }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Login failed. Please try again.");
      }

      toast.success("Success", {
        description: "You have successfully signed in!",
      });

      // If the user doesn't have WebAuthn set up,
      // prompt them to add it immediately after logging in
      if (data.canAddWebAuthn) {
        // Use a timeout to ensure the toast appears after navigation
        setTimeout(() => {
          toast.info("Add passkey to your account?", {
            description: "Would you like to add a passkey for easier login next time?",
            action: {
              label: "Add passkey",
              onClick: () => {
                handleAddWebAuthnCredential();
              },
            },
            duration: 10000, // Show this toast for longer
          });
        }, 1000);
      }
      
      router.push("/dashboard");
    } catch (error) {
      console.error("Passphrase login error:", error);
      setError((error as Error).message || "Login failed. Please try again.");
      toast.error("Error", {
        description:
          (error as Error).message || "Login failed. Please try again.",
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
              defaultValue={webAuthnSupported ? "webauthn" : "passphrase"}
              onValueChange={(value) =>
                setAuthTab(value as "webauthn" | "passphrase")
              }
              className="space-y-4"
            >
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="webauthn" disabled={!webAuthnSupported}>
                  {webAuthnSupported ? "Passkey" : "Passkey (Not Supported)"}
                </TabsTrigger>
                <TabsTrigger value="passphrase">Passphrase</TabsTrigger>
              </TabsList>

              <TabsContent value="webauthn" className="space-y-4">
                <div className="space-y-2">
                  <p className="text-sm">
                    {isNewUser
                      ? "Register with a passkey for passwordless authentication. This uses your device's biometrics or security features."
                      : "Sign in with your passkey."}
                  </p>
                  {!webAuthnSupported && (
                    <p className="text-sm text-amber-600">
                      Your browser or device doesn&apos;t support passkeys. Please use the passphrase option instead.
                    </p>
                  )}
                  {error && <p className="text-sm text-red-500">{error}</p>}
                  <Button
                    onClick={
                      isNewUser
                        ? handleWebAuthnRegistration
                        : handleWebAuthnLogin
                    }
                    className="w-full"
                    disabled={isLoading || !webAuthnSupported}
                  >
                    {isLoading
                      ? isNewUser
                        ? "Registering..."
                        : "Signing in..."
                      : isNewUser
                        ? "Register with Passkey"
                        : "Sign in with Passkey"}
                  </Button>
                  {isNewUser && (
                    <p className="text-xs text-muted-foreground">
                      Note: After registering with a passkey, you&apos;ll also set up a backup passphrase.
                    </p>
                  )}
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
                      disabled={isLoading}
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
