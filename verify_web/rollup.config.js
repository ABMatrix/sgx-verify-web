import svelte from "rollup-plugin-svelte";
import commonjs from "@rollup/plugin-commonjs";
import resolve from "@rollup/plugin-node-resolve";
import livereload from "rollup-plugin-livereload";
import { terser } from "rollup-plugin-terser";
import typescript from "@rollup/plugin-typescript";
import css from "rollup-plugin-css-only";
import sourcemaps from "rollup-plugin-sourcemaps";
import replace from "rollup-plugin-replace";
import sveltePreprocess from "svelte-preprocess";
import json from "@rollup/plugin-json";
import nodePolyfills from "rollup-plugin-node-polyfills";

const production = !process.env.ROLLUP_WATCH;

function serve() {
  let server;

  function toExit() {
    if (server) server.kill(0);
  }

  return {
    writeBundle() {
      if (server) return;
      server = require("child_process").spawn(
        "npm",
        ["run", "start", "--", "--dev"],
        {
          stdio: ["ignore", "inherit", "inherit"],
          shell: true,
        }
      );

      process.on("SIGTERM", toExit);
      process.on("exit", toExit);
    },
  };
}

export default {
  input: "src/main.ts",
  output: {
    sourcemap: true,
    format: "cjs",
    name: "app",
    file: "public/build/bundle.js",
    inlineDynamicImports: true,
  },
  plugins: [
    svelte({
      preprocess: sveltePreprocess({ sourceMap: !production, postcss: true }),
      compilerOptions: {
        // enable run-time checks when not in production
        dev: !production,
      },
    }),
    css({ output: "bundle.css" }),
    resolve({
      browser: true,
      dedupe: ["svelte"],
    }),
    commonjs(),
    typescript({
      sourceMap: !production,
      inlineSources: !production,
    }),

    // In dev mode, call `npm run start` once
    // the bundle has been generated
    !production && serve(),

    // Watch the `public` directory and refresh the
    // browser on changes when not in production
    !production && livereload("public"),

    // If we're building for production (npm run build
    // instead of npm run dev), minify
    production && terser(),
    sourcemaps(),
    json(),
    nodePolyfills(),
    replace({
      "process.env.NODE_ENV": JSON.stringify("development"),
    }),
  ],
  watch: {
    clearScreen: false,
  },
};
