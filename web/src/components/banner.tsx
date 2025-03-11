"use client";

import { useCallback } from "react";
import type { Engine } from "tsparticles-engine";
import Particles from "react-tsparticles";
import { loadSlim } from "tsparticles-slim";

export function Banner() {
  const particlesInit = useCallback(async (engine: Engine) => {
    await loadSlim(engine);
  }, []);

  return (
    <section 
      className="relative h-150 w-full overflow-hidden bg-gradient-to-br from-primary-500/90 via-tertiary-600/90 to-secondary-700/90 dark:from-primary-900/90 dark:via-tertiary-950/90 dark:to-secondary-950/90 backdrop-blur-sm"
      aria-label="Welcome banner with interactive particle effects"
    >
      <Particles
        className="absolute inset-0"
        id="tsparticles"
        init={particlesInit}
        options={{
          background: {
            opacity: 0,
          },
          fullScreen: {
            enable: false,
            zIndex: 0
          },
          fpsLimit: 120,
          interactivity: {
            events: {
              onClick: {
                enable: true,
                mode: "push",
              },
              onHover: {
                enable: true,
                mode: "repulse",
              },
              resize: true,
            },
            modes: {
              push: {
                quantity: 4,
              },
              repulse: {
                distance: 200,
                duration: 0.4,
              },
            },
          },
          particles: {
            color: {
              value: ["var(--color-surface-50)", "var(--color-surface-100)"]
            },
            links: {
              color: "var(--color-surface-50)",
              distance: 150,
              enable: true,
              opacity: 0.5,
              width: 1,
            },
            move: {
              direction: "none",
              enable: true,
              outModes: {
                default: "bounce",
              },
              random: false,
              speed: 2,
              straight: false,
            },
            number: {
              density: {
                enable: true,
                area: 800,
              },
              value: 80,
            },
            opacity: {
              value: 0.5,
            },
            shape: {
              type: "circle",
            },
            size: {
              value: { min: 1, max: 5 },
            },
          },
          detectRetina: true,
        }}
      />
      <div className="relative z-10 container mx-auto px-4 py-12 flex flex-col items-center text-center">
        <h1 className="text-4xl font-bold text-surface-50 tracking-tight">
          Welcome to NFE
          <span className="sr-only"> - Neural Flow Engine</span>
        </h1>
        <p className="mt-4 text-xl text-surface-100 max-w-2xl">
          Experience the future of neural flow computing with our advanced AI-powered platform
        </p>
        <div className="mt-8 flex items-center gap-4">
          <button 
            className="h-9 px-4 bg-primary-500 hover:bg-primary-600 dark:bg-primary-700 dark:hover:bg-primary-800 text-surface-50 rounded-md focus-visible:ring-1 focus-visible:ring-ring transition-colors"
            title="Start using NFE"
            aria-label="Get started with NFE"
          >
            Get Started
          </button>
          <button 
            className="h-9 px-4 bg-surface-50/10 hover:bg-surface-50/20 dark:bg-surface-700/50 dark:hover:bg-surface-700/70 text-surface-50 rounded-md focus-visible:ring-1 focus-visible:ring-ring transition-colors"
            title="Learn more about NFE"
            aria-label="Learn more about NFE features"
          >
            Learn More
          </button>
        </div>
      </div>
    </section>
  );
}
