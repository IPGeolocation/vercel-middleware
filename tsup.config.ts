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
  // Edge Runtime does not support Node.js built-ins — keep the bundle clean
  platform: 'browser',
  target: 'es2020',
  banner: {
    js: '/* ipgeolocation-vercel-middleware — https://ipgeolocation.io */'
  }
});
