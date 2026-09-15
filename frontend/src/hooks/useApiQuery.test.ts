import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useApiQuery } from "./useApiQuery";

describe("useApiQuery", () => {
  it("loads data per key and keeps the previous data while a new key loads", async () => {
    const { result, rerender } = renderHook(({ id }) => useApiQuery(id, () => Promise.resolve(`value-${id}`)), {
      initialProps: { id: "a" },
    });
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.data).toBe("value-a"));
    expect(result.current.loading).toBe(false);

    rerender({ id: "b" });
    expect(result.current.data).toBeUndefined();
    expect(result.current.previousData).toBe("value-a");
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.data).toBe("value-b"));
  });

  it("aborts the request for a key that is no longer wanted", () => {
    const signals: AbortSignal[] = [];
    const { rerender } = renderHook(
      ({ id }) =>
        useApiQuery(id, (signal) => {
          signals.push(signal);
          return new Promise<string>(() => undefined);
        }),
      { initialProps: { id: "a" } },
    );
    rerender({ id: "b" });
    expect(signals).toHaveLength(2);
    expect(signals[0]?.aborted).toBe(true);
    expect(signals[1]?.aborted).toBe(false);
  });

  it("reports failures as API errors", async () => {
    const { result } = renderHook(() => useApiQuery("broken", () => Promise.reject(new Error("Network down"))));
    await waitFor(() => expect(result.current.error?.message).toBe("Network down"));
    expect(result.current.loading).toBe(false);
  });

  it("does nothing for a null key", () => {
    const { result } = renderHook(() => useApiQuery<string>(null, () => Promise.resolve("unused")));
    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBeUndefined();
  });
});
