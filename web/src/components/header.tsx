"use client";

import * as React from "react";
import { AppBar, Switch } from "@skeletonlabs/skeleton-react";
import { Logo } from "@/components/logo";
import { SignIn } from "@/components/auth/signin";
import {
  Moon,
  Sun,
  Mic,
  SlidersVertical,
  Menu,
  Search,
} from "lucide-react";

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
        <AppBar.ToolbarCenter base="flex items-center w-1/2">
          <div className="relative w-full">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-surface-500 dark:text-surface-400 pointer-events-none" />
            <input
              type="text"
              placeholder="Search..."
              className="w-full h-13 pl-9 pr-4 bg-surface-100/50 hover:bg-surface-200/50 dark:bg-surface-800/50 dark:hover:bg-surface-700/50 border border-surface-300 dark:border-surface-600 rounded-full focus-visible:ring-1 focus-visible:ring-ring focus-visible:outline-none focus-visible:border-ring focus-visible:bg-surface-50 dark:focus-visible:bg-surface-900 transition-colors"
              aria-label="Search NFE"
            />
          </div>
        </AppBar.ToolbarCenter>
        <AppBar.ToolbarTrail base="flex items-center gap-6">
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
          <SignIn />
        </AppBar.ToolbarTrail>
      </AppBar.Toolbar>
    </AppBar>
  );
}
