---
"better-auth-dbsc": minor
---

Require Better Auth 1.7.25 or later (`better-auth` and `@better-auth/core` peer dependencies) and Node.js 26 or later (`engines`). `multiSession()` must now come before `dbsc()` in `plugins`; the plugin refuses to start otherwise, naming the plugin to move.
