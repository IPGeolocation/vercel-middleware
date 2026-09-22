import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'index.ts',
    middleware: 'middleware.ts'
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  // The Edge Runtime has no Node.js built-ins, so keep the bundle free of them.
  platform: 'browser',
  target: 'es2020',
  external: ['next', 'next/server'],
  banner: {
    js: '/* ipgeolocation-vercel-middleware | https://ipgeolocation.io */'
  }
});
