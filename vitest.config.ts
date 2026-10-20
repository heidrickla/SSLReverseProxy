import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    // server/ is the .NET tree; e2e/ is Playwright's; .claude/ can hold agent worktrees with a copy of this repo.
    exclude: [...configDefaults.exclude, 'server/**', 'e2e/**', '.claude/**'],
  },
});
