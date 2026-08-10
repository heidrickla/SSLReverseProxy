/// <reference types="vite/client" />

// Brings Vite's `import.meta.env` typings (DEV, PROD, MODE, ...) into scope.
// tsconfig sets `types: ["node"]`, which replaces the default auto-inclusion of
// every @types package, so vite/client has to be referenced explicitly - without
// this, `import.meta.env.DEV` builds fine but fails `tsc --noEmit`.
