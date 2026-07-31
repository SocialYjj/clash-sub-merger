import { afterEach, describe, expect, it, vi } from 'vitest';

import request from '../request.js';


afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});


describe('request retry policy', () => {
  it('does not replay write requests after a retryable server error', async () => {
    vi.stubGlobal('localStorage', {
      getItem: vi.fn(() => 'session-value'),
      removeItem: vi.fn(),
    });

    const adapter = vi.fn(async (config) => {
      const error = new Error('temporary failure');
      error.config = config;
      error.response = { status: 503 };
      throw error;
    });

    await expect(
      request.post('/api/subscriptions/sub_1/refresh', null, { adapter })
    ).rejects.toThrow('temporary failure');

    expect(adapter).toHaveBeenCalledTimes(1);
  });
});
