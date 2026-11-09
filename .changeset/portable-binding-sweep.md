---
"better-auth-dbsc": patch
---

Sweep dead bindings with one range condition per query, so the cleanup also runs on adapters that only query through indexes (such as Convex). It used to fail there with "cannot have more than one lower bound where clause" and never delete anything.
