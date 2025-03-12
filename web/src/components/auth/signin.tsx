"use client";

import { useState, useEffect } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Mail, LogIn, ArrowLeft, CheckCircle } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { sendOtpEmail, verifyOtp } from "@/app/actions/auth";

const emailFormSchema = z.object({
  email: z.string().email({ message: "Please enter a valid email address." }),
});

const otpFormSchema = z.object({
  otp: z.string().length(6, { message: "Verification code must be 6 digits." }),
});

export default function SignInDialog() {
  const [open, setOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showOtpForm, setShowOtpForm] = useState(false);
  const [email, setEmail] = useState("");
  const [otpValue, setOtpValue] = useState("");
  const [otpError, setOtpError] = useState("");
  const [verificationSuccess, setVerificationSuccess] = useState(false);

  const emailForm = useForm<z.infer<typeof emailFormSchema>>({
    resolver: zodResolver(emailFormSchema),
    defaultValues: {
      email: "",
    },
  });

  const otpForm = useForm<z.infer<typeof otpFormSchema>>({
    resolver: zodResolver(otpFormSchema),
    defaultValues: {
      otp: "",
    },
    values: {
      otp: otpValue,
    },
  });

  // Reset OTP value when showing/hiding OTP form
  useEffect(() => {
    if (showOtpForm) {
      // Small delay to ensure the form is fully rendered before resetting
      const timer = setTimeout(() => {
        setOtpValue("");
        setOtpError("");
        otpForm.reset({ otp: "" });
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [showOtpForm, otpForm]);

  async function onEmailSubmit(values: z.infer<typeof emailFormSchema>) {
    setIsSubmitting(true);

    try {
      // Send OTP to the user's email using Resend
      const result = await sendOtpEmail(values.email);

      if (result.success) {
        setEmail(values.email);
        // Clear OTP value before showing the form
        setOtpValue("");
        setOtpError("");
        otpForm.reset({ otp: "" });
        setShowOtpForm(true);
        toast.success("Verification code sent", {
          description: `We've sent a code to ${values.email}`,
        });
      } else {
        toast.error("Error", {
          description: result.error || "Failed to send verification code",
        });
      }
    } catch (error) {
      console.error("Error sending OTP:", error);
      toast.error("Error", {
        description: "An unexpected error occurred",
      });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function onOtpSubmit(values: z.infer<typeof otpFormSchema>) {
    setIsSubmitting(true);
    setOtpError("");

    try {
      // Verify the OTP
      const result = await verifyOtp(email, values.otp);

      if (result.success) {
        // OTP verification successful
        setVerificationSuccess(true);
        toast.success("Success", {
          description: "You have successfully verified your email",
        });
        // Don't close the dialog, show success message instead
      } else {
        // Set specific error message for invalid OTP
        setOtpError(
          result.error || "Invalid verification code. Please try again."
        );
        toast.error("Error", {
          description: result.error || "Invalid verification code",
        });
      }
    } catch (error) {
      console.error("Error verifying OTP:", error);
      setOtpError("An unexpected error occurred. Please try again.");
      toast.error("Error", {
        description: "An unexpected error occurred",
      });
    } finally {
      setIsSubmitting(false);
    }
  }

  function resetDialog() {
    if (!open) {
      setShowOtpForm(false);
      setEmail("");
      setOtpValue("");
      setOtpError("");
      setVerificationSuccess(false);
      emailForm.reset();
      otpForm.reset({ otp: "" });
    }
  }

  // Function to handle OTP changes and keep our state in sync
  function handleOtpChange(value: string) {
    setOtpValue(value);
    otpForm.setValue("otp", value);
    // Clear error when user starts typing again
    if (otpError) {
      setOtpError("");
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(newOpen) => {
        setOpen(newOpen);
        resetDialog();
      }}
    >
      <DialogTrigger asChild>
        <LogIn size={30} className="cursor-pointer" />
      </DialogTrigger>
      <DialogContent className="sm:max-w-[425px]">
        {verificationSuccess ? (
          // Success view after verification
          <div className="py-6 flex flex-col items-center text-center space-y-4">
            <CheckCircle className="h-16 w-16 text-green-500" />
            <h2 className="text-2xl font-semibold">Email Verified</h2>
            <p className="text-muted-foreground">
              You have successfully verified your email address.
            </p>
            <Button
              className="mt-4"
              onClick={() => {
                setOpen(false);
                resetDialog();
              }}
            >
              Continue
            </Button>
          </div>
        ) : (
          // Regular sign-in flow
          <>
            <DialogHeader>
              <DialogTitle>
                {showOtpForm
                  ? "Enter verification code"
                  : "Sign in to your account"}
              </DialogTitle>
              <DialogDescription>
                {showOtpForm
                  ? `We've sent a 6-digit code to ${email}. Enter it below to verify.`
                  : "Enter your email address to sign in or create an account."}
              </DialogDescription>
            </DialogHeader>

            {!showOtpForm ? (
              <Form {...emailForm}>
                <form
                  onSubmit={emailForm.handleSubmit(onEmailSubmit)}
                  className="space-y-4 py-4"
                >
                  <FormField
                    control={emailForm.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Email</FormLabel>
                        <FormControl>
                          <div className="flex items-center">
                            <div className="relative flex-1">
                              <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                              <Input
                                placeholder="name@example.com"
                                className="pl-10"
                                {...field}
                              />
                            </div>
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <DialogFooter>
                    <Button
                      type="submit"
                      className="w-full"
                      disabled={isSubmitting}
                    >
                      {isSubmitting ? "Sending code..." : "Continue with Email"}
                    </Button>
                  </DialogFooter>
                </form>
              </Form>
            ) : (
              <Form {...otpForm}>
                <form
                  onSubmit={otpForm.handleSubmit(onOtpSubmit)}
                  className="space-y-4 py-4"
                  key="otp-form" // Force re-render when switching to OTP form
                >
                  <FormField
                    control={otpForm.control}
                    name="otp"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Verification Code</FormLabel>
                        <FormControl>
                          <div className="flex justify-center">
                            <InputOTP
                              maxLength={6}
                              value={otpValue}
                              onChange={handleOtpChange}
                              onBlur={field.onBlur}
                              name={field.name}
                              ref={field.ref}
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
                        </FormControl>
                        {/* Display OTP-specific error message */}
                        {otpError && (
                          <div className="text-sm font-medium text-destructive mt-2">
                            {otpError}
                          </div>
                        )}
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <div className="flex justify-between items-center text-sm">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="gap-1"
                      onClick={() => {
                        setOtpValue("");
                        setOtpError("");
                        otpForm.reset({ otp: "" });
                        setShowOtpForm(false);
                      }}
                    >
                      <ArrowLeft className="h-4 w-4" /> Back
                    </Button>
                    <Button
                      type="button"
                      variant="link"
                      className="px-0"
                      onClick={async () => {
                        setIsSubmitting(true);
                        const result = await sendOtpEmail(email);
                        setIsSubmitting(false);

                        if (result.success) {
                          // Reset OTP form after resending
                          setOtpValue("");
                          setOtpError("");
                          otpForm.reset({ otp: "" });
                          toast.success("Code resent", {
                            description:
                              "A new verification code has been sent to your email",
                          });
                        } else {
                          toast.error("Error", {
                            description:
                              result.error || "Failed to resend code",
                          });
                        }
                      }}
                      disabled={isSubmitting}
                    >
                      Resend code
                    </Button>
                  </div>
                  <DialogFooter>
                    <Button
                      type="submit"
                      className="w-full"
                      disabled={isSubmitting}
                    >
                      {isSubmitting ? "Verifying..." : "Verify and Sign In"}
                    </Button>
                  </DialogFooter>
                </form>
              </Form>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
