import { describe, expect, it } from 'vitest';

import { COUNTRY_CHINESE_NAMES, COUNTRY_COORDINATES, COUNTRY_NAME_MAP } from '../countryData.js';

describe('country map data', () => {
  it('contains key Chinese labels for major node regions', () => {
    expect(COUNTRY_CHINESE_NAMES.US).toBe('美国');
    expect(COUNTRY_CHINESE_NAMES.SG).toBe('新加坡');
    expect(COUNTRY_CHINESE_NAMES.HK).toBe('中国香港');
    expect(COUNTRY_CHINESE_NAMES.TW).toBe('中国台湾');
    expect(COUNTRY_CHINESE_NAMES.GF).toBe('法属圭亚那');
    expect(COUNTRY_CHINESE_NAMES.RE).toBe('留尼汪');
  });

  it('keeps coordinates in [longitude, latitude] order', () => {
    expect(COUNTRY_COORDINATES.US).toEqual([-95.7129, 37.0902]);
    expect(COUNTRY_COORDINATES.JP).toEqual([138.2529, 36.2048]);
    expect(COUNTRY_COORDINATES.SG).toEqual([103.8198, 1.3521]);
  });

  it('normalizes common English aliases from map features', () => {
    expect(COUNTRY_NAME_MAP['united states of america']).toBe('US');
    expect(COUNTRY_NAME_MAP.usa).toBe('US');
    expect(COUNTRY_NAME_MAP.uk).toBe('GB');
    expect(COUNTRY_NAME_MAP.hongkong).toBe('HK');
    expect(COUNTRY_NAME_MAP['french guiana']).toBe('GF');
    expect(COUNTRY_NAME_MAP['réunion']).toBe('RE');
  });
});
