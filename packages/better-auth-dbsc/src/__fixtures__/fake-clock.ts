import { afterEach, beforeEach, vi } from "vitest";

// Tests move the clock (registration grace, cookie expiry) with
// vi.setSystemTime; only Date is faked, so I/O and crypto run normally.
beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true, toFake: ["Date"] });
});

afterEach(() => {
  vi.useRealTimers();
});
