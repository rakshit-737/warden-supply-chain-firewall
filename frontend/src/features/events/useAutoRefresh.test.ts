import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAutoRefresh, type AutoRefreshOptions } from "./useAutoRefresh";

function setVisibility(state: DocumentVisibilityState) {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
  document.dispatchEvent(new Event("visibilitychange"));
}

describe("useAutoRefresh", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    Reflect.deleteProperty(document, "visibilityState");
    vi.useRealTimers();
  });

  it("refreshes on the interval, counted from when the data was fetched", () => {
    const onRefresh = vi.fn();
    const fetchedAt = Date.now() - 10_000;
    renderHook(() => useAutoRefresh({ enabled: true, intervalMs: 30_000, onRefresh, lastUpdatedAt: fetchedAt }));

    act(() => void vi.advanceTimersByTime(19_999));
    expect(onRefresh).not.toHaveBeenCalled();
    act(() => void vi.advanceTimersByTime(1));
    expect(onRefresh).toHaveBeenCalledTimes(1);
    act(() => void vi.advanceTimersByTime(30_000));
    expect(onRefresh).toHaveBeenCalledTimes(2);
  });

  it("pauses while the tab is hidden and refreshes at once when it is shown again", () => {
    const onRefresh = vi.fn();
    const fetchedAt = Date.now();
    const { result } = renderHook(() => useAutoRefresh({ enabled: true, intervalMs: 30_000, onRefresh, lastUpdatedAt: fetchedAt }));

    act(() => setVisibility("hidden"));
    expect(result.current.hidden).toBe(true);
    act(() => void vi.advanceTimersByTime(120_000));
    expect(onRefresh).not.toHaveBeenCalled();

    act(() => setVisibility("visible"));
    expect(result.current.hidden).toBe(false);
    act(() => void vi.advanceTimersByTime(0));
    expect(onRefresh).toHaveBeenCalledTimes(1);
  });

  it("does not poll when disabled, and skips a due refresh while a request is still running", () => {
    const onRefresh = vi.fn();
    const fetchedAt = Date.now();
    const { rerender } = renderHook((props: AutoRefreshOptions) => useAutoRefresh(props), {
      initialProps: { enabled: false, intervalMs: 30_000, onRefresh, lastUpdatedAt: fetchedAt, busy: false },
    });
    act(() => void vi.advanceTimersByTime(90_000));
    expect(onRefresh).not.toHaveBeenCalled();

    rerender({ enabled: true, intervalMs: 30_000, onRefresh, lastUpdatedAt: Date.now(), busy: true });
    act(() => void vi.advanceTimersByTime(30_000));
    expect(onRefresh).not.toHaveBeenCalled();

    rerender({ enabled: true, intervalMs: 30_000, onRefresh, lastUpdatedAt: Date.now() - 30_000, busy: false });
    act(() => void vi.advanceTimersByTime(30_000));
    expect(onRefresh).toHaveBeenCalled();
  });
});
