import { afterEach, describe, expect, it, vi } from 'vitest';

import { copyToClipboard } from '../clipboard.js';

const makeDocumentStub = (execResult = true) => {
  const appended = [];
  const textarea = {
    value: '',
    style: {},
    setAttribute: vi.fn(),
    focus: vi.fn(),
    select: vi.fn(),
  };
  return {
    textarea,
    body: {
      appendChild: vi.fn((node) => appended.push(node)),
      removeChild: vi.fn((node) => {
        const index = appended.indexOf(node);
        if (index !== -1) appended.splice(index, 1);
      }),
    },
    createElement: vi.fn(() => textarea),
    execCommand: vi.fn(() => execResult),
  };
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('copyToClipboard', () => {
  it('uses navigator clipboard when available', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });

    await expect(copyToClipboard('hello')).resolves.toBe(true);

    expect(writeText).toHaveBeenCalledWith('hello');
  });

  it('falls back to textarea copy when navigator clipboard fails', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('permission denied'));
    const documentStub = makeDocumentStub(true);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    vi.stubGlobal('document', documentStub);

    await expect(copyToClipboard('fallback text')).resolves.toBe(true);

    expect(documentStub.createElement).toHaveBeenCalledWith('textarea');
    expect(documentStub.textarea.value).toBe('fallback text');
    expect(documentStub.execCommand).toHaveBeenCalledWith('copy');
    expect(documentStub.body.removeChild).toHaveBeenCalledWith(documentStub.textarea);
  });

  it('returns false when no clipboard method is available', async () => {
    vi.stubGlobal('navigator', {});
    vi.stubGlobal('document', { body: null });

    await expect(copyToClipboard('nope')).resolves.toBe(false);
  });
});
