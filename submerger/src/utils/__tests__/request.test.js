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


describe('request error detail formatting', () => {
  it('flattens FastAPI validation detail instead of rendering [object Object]', async () => {
    vi.stubGlobal('localStorage', {
      getItem: vi.fn(() => 'session-value'),
      removeItem: vi.fn(),
    });

    const adapter = vi.fn(async (config) => {
      const error = new Error('Request failed with status code 422');
      error.config = config;
      error.response = {
        status: 422,
        data: {
          detail: [
            {
              loc: ['body', 'node'],
              msg: 'Value error, Node metadata fields cannot be changed',
              type: 'value_error',
            },
            {
              loc: ['body', 'node', 'port'],
              msg: 'Input should be a valid integer',
              type: 'int_parsing',
            },
          ],
        },
      };
      throw error;
    });

    const failure = await request
      .put('/api/custom-nodes/node_1/full', { node: {} }, { adapter })
      .catch(error => error);

    expect(failure.response.data.detail).toBe(
      'node: Value error, Node metadata fields cannot be changed; '
      + 'node.port: Input should be a valid integer'
    );
  });
});
