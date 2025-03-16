"use client";

import { Button } from "@/components/ui/button";
import { useRouter } from "next/navigation";

export function HeaderSignIn() {
  const router = useRouter();

  return (
    <Button
      variant="ghost"
      onClick={() => router.push("/auth/signin")}
      className="hover:bg-surface-700 dark:hover:bg-surface-700"
    >
      Sign In
    </Button>
  );
}
