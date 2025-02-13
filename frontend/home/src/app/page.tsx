"use client";

import { useState } from "react";
import { signIn } from "next-auth/react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";

const GENERATE_OTP_QUERY = `
  query GenerateOTP($req: GenerateOTPRequestInput) {
    generateOTP(req: $req) {
      success
      message
    }
  }
`;

const VERIFY_OTP_QUERY = `
  query VerifyOTP($req: VerifyOTPRequestInput) {
    verifyOTP(req: $req) {
      success
      message
      token
      user {
        iD
        email
      }
    }
  }
`;

const GET_USER_TIMESTAMPS_QUERY = `
  query($req: GetUserTimestampsInput) {
    userTimestamps(req: $req) {
      dateJoined
      lastAuthTime
    }
  }
`;

export default function Home() {
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState<"email" | "otp" | "success">("email");
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [timestamps, setTimestamps] = useState<{ dateJoined?: string; lastAuthTime?: string } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('http://localhost:8686/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query: GENERATE_OTP_QUERY,
          variables: {
            req: {
              email
            }
          }
        })
      });

      const data = await response.json();

      if (data.errors) {
        throw new Error(data.errors[0].message);
      }

      if (data.data?.generateOTP?.success) {
        setStep("otp");
        setError(null);
        console.log("OTP Generated:", data.data.generateOTP.message);
      } else {
        throw new Error(data.data?.generateOTP?.message || "Failed to generate OTP");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (otp.length !== 6) {
      setError("Please enter all 6 digits");
      return;
    }
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('http://localhost:8686/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query: VERIFY_OTP_QUERY,
          variables: {
            req: {
              email,
              oTP: otp
            }
          }
        })
      });

      const data = await response.json();

      if (data.errors) {
        throw new Error(data.errors[0].message);
      }

      if (data.data?.verifyOTP?.success) {
        const { token, user } = data.data.verifyOTP;
        
        // Sign in with Auth.js using the JWT
        const result = await signIn("credentials", {
          token,
          user: JSON.stringify(user),
          redirect: false,
        });

        if (result?.error) {
          throw new Error(result.error);
        }

        // Fetch user timestamps
        const timestampsResponse = await fetch('http://localhost:8686/graphql', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            query: GET_USER_TIMESTAMPS_QUERY,
            variables: {
              req: {
                email
              }
            }
          })
        });

        const timestampsData = await timestampsResponse.json();
        if (timestampsData.data?.userTimestamps) {
          setTimestamps(timestampsData.data.userTimestamps);
        }

        setStep("success");
      } else {
        throw new Error(data.data?.verifyOTP?.message || "Failed to verify OTP");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setIsDialogOpen(false);
    setStep("email");
    setOtp("");
    setEmail("");
    setError(null);
  };

  return (
    <div className="flex items-center justify-center min-h-screen">
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogTrigger asChild>
          <button className="btn variant-filled-primary">Open Dialog</button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {step === "email" ? "Enter Your Email" : 
               step === "otp" ? "Enter OTP" :
               "Verification Successful"}
            </DialogTitle>
            <DialogDescription>
              {step === "email" 
                ? "Please provide your email address to continue."
                : step === "otp"
                ? "Please enter the 6-digit code sent to your email."
                : "Here are your account details:"}
            </DialogDescription>
          </DialogHeader>
          {step === "email" ? (
            <form onSubmit={handleSubmit} className="p-4 space-y-4">
              <label className="label">
                <span className="label-text">Email</span>
                <input
                  type="email"
                  placeholder="you@example.com"
                  className="input"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={loading}
                />
              </label>
              {error && (
                <div className="text-red-500 text-sm mt-2">
                  {error}
                </div>
              )}
              <div className="flex justify-end">
                <button 
                  type="submit" 
                  className="btn variant-filled"
                  disabled={loading}
                >
                  {loading ? "Submitting..." : "Submit"}
                </button>
              </div>
            </form>
          ) : step === "otp" ? (
            <form onSubmit={handleVerifyOtp} className="p-4 space-y-4">
              <div className="flex flex-col items-center space-y-4">
                <InputOTP
                  maxLength={6}
                  value={otp}
                  onChange={setOtp}
                  disabled={loading}
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
              {error && (
                <div className="text-red-500 text-sm mt-2">
                  {error}
                </div>
              )}
              <div className="flex justify-end gap-2">
                <button 
                  type="button" 
                  className="btn variant-soft"
                  onClick={() => {
                    setStep("email");
                    setOtp("");
                    setError(null);
                  }}
                >
                  Back
                </button>
                <button 
                  type="submit" 
                  className="btn variant-filled"
                  disabled={loading}
                >
                  {loading ? "Verifying..." : "Verify OTP"}
                </button>
              </div>
            </form>
          ) : (
            <div className="p-4 space-y-4">
              <div className="space-y-2">
                <div>
                  <span className="font-semibold">You have been successfully verified.</span>
                </div>
              </div>
              {timestamps && (
                <div className="mt-4 space-y-2 text-sm text-gray-600">
                  {timestamps.dateJoined && (
                    <p>Member since: {new Date(timestamps.dateJoined).toLocaleDateString()}</p>
                  )}
                  {timestamps.lastAuthTime && (
                    <p>Last login: {new Date(timestamps.lastAuthTime).toLocaleDateString()}</p>
                  )}
                </div>
              )}
              <div className="flex justify-end">
                <button 
                  type="button" 
                  className="btn variant-filled"
                  onClick={handleClose}
                >
                  Close
                </button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
