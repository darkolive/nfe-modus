"use client";

import * as React from "react";
import { AppBar, Switch } from "@skeletonlabs/skeleton-react";
import { Logo } from "@/components/logo";
import { Moon, Sun, Mic, SlidersVertical, Menu, LogIn } from "lucide-react";

export function Header() {
  const [mounted, setMounted] = React.useState(false);
  const [isDark, setIsDark] = React.useState(false);

  // Handle initial mount to prevent hydration mismatch
  React.useEffect(() => {
    setIsDark(document.documentElement.classList.contains("dark"));
    setMounted(true);
  }, []);

  function handleDarkMode(newValue: boolean) {
    setIsDark(newValue);
    // Toggle dark class on html element for Tailwind
    document.documentElement.classList.toggle("dark", newValue);
  }

  // Prevent hydration mismatch by only rendering after mount
  if (!mounted) return null;

  return (
    <AppBar
      base={
        "px-12 fixed top-0 left-0 right-0 z-50 bg-surface-300 dark:bg-surface-700"
      }
    >
      <AppBar.Toolbar>
        <AppBar.ToolbarLead>
          <div className="flex items-center gap-4">
            <Logo />
            <span className="text-3xl font-semibold">NFE</span>
          </div>
        </AppBar.ToolbarLead>
        <AppBar.ToolbarCenter>
          <div className="rounded-full"></div>
        </AppBar.ToolbarCenter>
        <AppBar.ToolbarTrail>
          <div className="flex items-center gap-4">
            <Switch
              name="darkmode"
              controlActive="bg-surface-700"
              checked={isDark}
              onCheckedChange={(e) => handleDarkMode(e.checked)}
              inactiveChild={<Sun size="14" />}
              activeChild={<Moon size="14" />}
            />
            <Mic size={20} />
            <SlidersVertical size={20} />
            <Menu size={20} />
            <LogIn size={20} />
          </div>
        </AppBar.ToolbarTrail>
      </AppBar.Toolbar>
    </AppBar>
  );
}
