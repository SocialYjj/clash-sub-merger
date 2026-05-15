import { describe, expect, it } from 'vitest';

import { formatTraffic, getTrafficInfo, getAvatarTheme } from '../format.js';

describe('format utilities', () => {
  it('formats traffic values across MB, GB and TB ranges', () => {
    expect(formatTraffic(null)).toBeNull();
    expect(formatTraffic(0)).toBe('0.00 MB');
    expect(formatTraffic(1024 * 1024)).toBe('1.00 MB');
    expect(formatTraffic(1024 * 1024 * 1024)).toBe('1.00 GB');
    expect(formatTraffic(1024 * 1024 * 1024 * 1024)).toBe('1.00 TB');
  });

  it('builds subscription traffic summary with capped percent', () => {
    const info = getTrafficInfo({
      upload: 6 * 1024 * 1024 * 1024,
      download: 6 * 1024 * 1024 * 1024,
      total: 10 * 1024 * 1024 * 1024,
      expire: 0,
    });

    expect(info.used).toBe('12.00 GB');
    expect(info.total).toBe('10.00 GB');
    expect(info.percent).toBe('100.0');
    expect(info.expire).toBeNull();
  });

  it('returns a stable avatar theme for the same name', () => {
    expect(getAvatarTheme('SubMerger')).toEqual(getAvatarTheme('SubMerger'));
  });
});
