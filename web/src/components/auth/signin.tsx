import * as React from "react";
import { useFloating, FloatingPortal, FloatingOverlay, FloatingFocusManager, offset, autoUpdate } from '@floating-ui/react';
import { LogIn } from "lucide-react";

export function SignIn() {
  const [isOpen, setIsOpen] = React.useState(false);
  const [email, setEmail] = React.useState("");
  const [otp, setOtp] = React.useState("");
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [showOtpInput, setShowOtpInput] = React.useState(false);
  const [message, setMessage] = React.useState<{ text: string; type: 'success' | 'error' | null }>({ text: '', type: null });

  const { refs, context } = useFloating({
    open: isOpen,
    onOpenChange: setIsOpen,
    middleware: [offset(8)],
    whileElementsMounted: autoUpdate
  });

  const handleClose = () => {
    setIsOpen(false);
    setMessage({ text: '', type: null });
  };

  const handleSendOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setMessage({ text: '', type: null });

    try {
      const response = await fetch("/api/auth/send-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();
      if (data.success) {
        setShowOtpInput(true);
        setMessage({ text: "OTP sent to your email", type: 'success' });
      } else {
        setMessage({ text: data.error || "Failed to send OTP", type: 'error' });
      }
    } catch {
      setMessage({ text: "Failed to send OTP", type: 'error' });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setMessage({ text: '', type: null });

    try {
      const response = await fetch("/api/auth/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otp }),
      });

      const data = await response.json();
      if (data.success) {
        setMessage({ text: "OTP verified successfully", type: 'success' });
        // Wait a moment to show the success message before closing
        setTimeout(() => {
          setIsOpen(false);
          setShowOtpInput(false);
          setEmail("");
          setOtp("");
          setMessage({ text: '', type: null });
        }, 1500);
      } else {
        setMessage({ text: data.error || "Invalid OTP", type: 'error' });
      }
    } catch {
      setMessage({ text: "Failed to verify OTP", type: 'error' });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <button
        ref={refs.setReference}
        onClick={() => setIsOpen(true)}
        className="variant-ghost-surface hover:variant-soft-surface dark:hover:bg-surface-700 rounded-lg p-2"
      >
        <LogIn size={32} />
      </button>

      {isOpen && (
        <FloatingPortal>
          <FloatingOverlay
            className="fixed inset-0 bg-surface-900/50 backdrop-blur-sm z-50"
            lockScroll
          >
            <FloatingFocusManager context={context}>
              <div
                ref={refs.setFloating}
                className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-surface-50 dark:bg-surface-800 rounded-lg shadow-lg p-6"
              >
                <div className="flex flex-col space-y-4">
                  <div className="flex justify-between items-center mb-4">
                    <h2 className="text-xl font-semibold text-surface-900 dark:text-surface-50">
                      Sign In
                    </h2>
                    <button
                      onClick={handleClose}
                      className="text-surface-500 hover:text-surface-700 dark:text-surface-400 dark:hover:text-surface-200"
                    >
                      ✕
                    </button>
                  </div>

                  {message.text && (
                    <div className={`p-3 rounded ${
                      message.type === 'success' 
                        ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300' 
                        : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
                    }`}>
                      {message.text}
                    </div>
                  )}

                  <form onSubmit={showOtpInput ? handleVerifyOtp : handleSendOtp} className="space-y-4">
                    <div className="space-y-2">
                      <label
                        htmlFor="email"
                        className="block text-sm font-medium text-surface-700 dark:text-surface-300"
                      >
                        {showOtpInput ? `Email (${email})` : 'Email'}
                      </label>
                      <input
                        id="email"
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        disabled={showOtpInput || isSubmitting}
                        className="w-full h-10 px-3 bg-surface-50 dark:bg-surface-900 border border-surface-300 dark:border-surface-600 rounded-lg focus-visible:ring-1 focus-visible:ring-ring focus-visible:outline-none"
                      />
                    </div>

                    {showOtpInput && (
                      <div className="space-y-2">
                        <label
                          htmlFor="otp"
                          className="block text-sm font-medium text-surface-700 dark:text-surface-300"
                        >
                          Enter OTP
                        </label>
                        <input
                          id="otp"
                          type="text"
                          value={otp}
                          onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                          required
                          disabled={isSubmitting}
                          pattern="[0-9]{6}"
                          inputMode="numeric"
                          maxLength={6}
                          placeholder="000000"
                          className="w-full h-10 px-3 text-center tracking-widest bg-surface-50 dark:bg-surface-900 border border-surface-300 dark:border-surface-600 rounded-lg focus-visible:ring-1 focus-visible:ring-ring focus-visible:outline-none"
                        />
                      </div>
                    )}

                    <div className="flex justify-end gap-2 mt-6">
                      <button
                        type="button"
                        onClick={handleClose}
                        disabled={isSubmitting}
                        className="variant-ghost-surface hover:variant-soft-surface dark:hover:bg-surface-700 h-10 px-4 rounded-lg"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        disabled={isSubmitting || (!showOtpInput && !email) || (showOtpInput && !otp)}
                        className="variant-filled-primary hover:variant-soft-primary dark:bg-primary-700 h-10 px-4 rounded-lg disabled:opacity-50"
                      >
                        {isSubmitting ? 'Loading...' : showOtpInput ? 'Verify Code' : 'Get Code'}
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            </FloatingFocusManager>
          </FloatingOverlay>
        </FloatingPortal>
      )}
    </>
  );
}
