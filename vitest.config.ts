import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    // server/ is the .NET tree; .claude/ can hold agent worktrees with a copy of this repo.
    exclude: [...configDefaults.exclude, 'server/**', '.claude/**'],
  },
});
