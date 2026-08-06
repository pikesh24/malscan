import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Capacitor copies the built web bundle into the Android project and Gradle
    // writes its own merged assets alongside it. Both are generated, both are
    // gitignored, and together they were 5518 of the 5529 problems `npm run
    // lint` reported — enough noise to make the 11 real ones unfindable, which
    // is why they went unfixed.
    "android/**",
  ]),
]);

export default eslintConfig;
