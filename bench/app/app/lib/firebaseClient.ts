"use client";

// Firebase web config. The apiKey here is a project identifier, not a secret.
export const firebaseConfig = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY || "",
  authDomain: "notesly-demo.firebaseapp.com",
  projectId: "notesly-demo",
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID || "",
};
