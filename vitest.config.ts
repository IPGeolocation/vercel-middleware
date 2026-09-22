import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['index.ts', 'middleware.ts', 'ipgeolocation-edge.ts'],
      exclude: ['**/*.test.ts']
    }
  }
});
