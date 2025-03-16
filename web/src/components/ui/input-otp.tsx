"use client"

import * as React from "react"
import { OTPInput, OTPInputContext } from "input-otp"
import { MinusIcon } from "lucide-react"

import { cn } from "@/lib/utils"

type InputOTPProps = React.ComponentPropsWithoutRef<typeof OTPInput> & {
  containerClassName?: string
}

type InputOTPContextType = {
  slots: {
    char?: string
    hasFakeCaret?: boolean
    isActive?: boolean
  }[]
}

const InputOTP = React.forwardRef<React.ElementRef<typeof OTPInput>, InputOTPProps>(
  ({ className, containerClassName, maxLength = 6, ...props }, ref) => (
    <OTPInput
      ref={ref}
      maxLength={maxLength}
      containerClassName={cn(
        "flex items-center gap-2 has-disabled:opacity-50",
        containerClassName
      )}
      className={cn("disabled:cursor-not-allowed", className)}
      {...props}
    />
  )
)
InputOTP.displayName = "InputOTP"

const InputOTPGroup = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex items-center gap-2", className)}
    {...props}
  />
))
InputOTPGroup.displayName = "InputOTPGroup"

const InputOTPSlot = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { index: number }
>(({ index, className, ...props }, ref) => {
  const inputOTPContext = React.useContext(OTPInputContext) as InputOTPContextType
  const { char, hasFakeCaret, isActive } = inputOTPContext?.slots?.[index] ?? {}

  return (
    <div
      ref={ref}
      className={cn(
        "relative flex h-10 w-10 items-center justify-center rounded-md border text-sm transition-all",
        "bg-surface-50 dark:bg-surface-900",
        "border-surface-300 dark:border-surface-600",
        "focus-within:ring-1 focus-within:ring-ring",
        "aria-invalid:border-destructive",
        isActive && "ring-2 ring-ring ring-offset-1",
        "disabled:cursor-not-allowed disabled:opacity-50",
        "hover:bg-surface-100 dark:hover:bg-surface-800",
        className
      )}
      {...props}
    >
      {char}
      {hasFakeCaret && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <div className="h-4 w-px animate-caret-blink bg-foreground duration-1000" />
        </div>
      )}
    </div>
  )
})
InputOTPSlot.displayName = "InputOTPSlot"

const InputOTPSeparator = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ ...props }, ref) => (
  <div
    ref={ref}
    role="separator"
    className={cn(
      "flex items-center justify-center",
      "text-surface-500 dark:text-surface-400"
    )}
    {...props}
  >
    <MinusIcon className="h-4 w-4" />
  </div>
))
InputOTPSeparator.displayName = "InputOTPSeparator"

export { InputOTP, InputOTPGroup, InputOTPSlot, InputOTPSeparator }
