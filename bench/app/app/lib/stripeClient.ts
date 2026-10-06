"use client";

// Publishable key for Stripe.js in the browser. Publishable keys are public.
export const stripePublishableKey =
  process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY || "";
