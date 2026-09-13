import { COUNTRY_CHINESE_NAMES } from '../countryData';

const INFO_PREFIX_RE = /^\s*(?:建议|通知|公告|提示|说明|使用前|更新订阅|套餐到期|剩余流量)\s*[:：]?/i;
const INFO_DOMAIN_HINT_RE = /^\s*(?:最强备用|备用网址|备用地址|官网地址?|防丢失官网?|防失联官网?|永久官网|永久地址|最新官网|最新地址|网址发布|域名发布|防丢失|防失联)\s*[:：]?\s*(?:https?:\/\/)?(?:[A-Za-z0-9\u4e00-\u9fff-]+\.)+[A-Za-z]{2,}(?:\/\S*)?\s*$/i;
const INFO_TIMESTAMP_RE = /^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s*\(UTC[+-]\d{1,2}(?::?\d{2})?\)\s*$/i;
const INFO_BALANCE_RE = /^\s*(?:balance|余额)\s*[:：]\s*\d+(?:[.,]\d+)?\s*(?:[KMGTPE]i?B|B)\s*$/i;
const INFO_WEBSITE_RE = /^\s*(?:website|网站|网址)\s*[:：]\s*(?:https?:\/\/)?(?:[A-Za-z0-9\u4e00-\u9fff-]+\.)+[A-Za-z]{2,}(?:\/\S*)?\s*$/i;
const OFFICIAL_URL_RE = /https?:\/\//i;

const HARD_INVALID_KEYWORDS = [
  '剩余流量', '套餐到期', '距离下次重置', '未到期', '使用前',
  '使用说明', '教程', '更新订阅', '公告', '通知', '客服',
  '续费', '购买', '工单', '咨询', '合作', '邀请', '返利',
  '免注册', '免费节点', '变动较大', '全超时', '更换客户端',
  '关注', '版本', '须知', '频道', '维护', '公众号'
];

const SOFT_INVALID_KEYWORDS = [
  '建议', '剩余', '到期', '重置', '流量', '过期', '订阅',
  '网址', '群组', 'Telegram', 'TG', '会员', '商城', '账号'
];

// Complete region names from COUNTRY_CHINESE_NAMES (236 countries/regions)
const REGION_KEYWORDS = [
  ...Object.values(COUNTRY_CHINESE_NAMES),  // All 236 Chinese country names
  // Common abbreviations and English names
  'HK', 'TW', 'MO', 'JP', 'KR', 'SG', 'US', 'UK',
  'DE', 'FR', 'CA', 'AU', 'RU', 'IN', 'TH', 'VN', 'MY', 'PH', 'ID',
  'CN', 'GB', 'IT', 'ES', 'PT', 'NL', 'BE', 'CH', 'AT', 'CZ', 'PL',
  'SE', 'NO', 'FI', 'DK', 'IE', 'NZ', 'BR', 'AR', 'CL', 'MX', 'TR',
  'SA', 'AE', 'IL', 'EG', 'ZA', 'NG', 'KE', 'UA', 'BY', 'KZ', 'UZ',
  '海外',  // Generic "overseas"
  // Short forms for Chinese regions (COUNTRY_CHINESE_NAMES has "China Hong Kong" but nodes use "Hong Kong")
  '香港', '台湾', '澳门'
];

const STRONG_NODE_HINTS = [
  '节点', '备用', '家宽', '专线', '中转', '落地', '倍率',
  '游戏', '住宅', '原生'
];

const LINE_INDEX_RE = /--\s*\d+\b|\(\s*\d+\s*\)$/;
export const LEADING_FLAG_ICON_RE = /^(?:[\u{1F1E6}-\u{1F1FF}]{2}|🔰|🌏|🌍|🌎|🏳️)\s*/u;

const hasRegionHint = (name) => {
  return REGION_KEYWORDS.some(region => {
    if (region.length <= 3 && /^[A-Z]+$/.test(region)) {
      const escaped = region.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(?<![A-Za-z])${escaped}(?:\\d+)?(?![A-Za-z])`).test(name);
    }
    return name.includes(region);
  });
};

const hasNodeIdentity = (name) => {
  if (hasRegionHint(name)) return true;
  if (LINE_INDEX_RE.test(name)) return true;
  return STRONG_NODE_HINTS.some(hint => name.includes(hint));
};

export const stripLeadingFlagIcon = (value) => String(value || '').replace(LEADING_FLAG_ICON_RE, '').trim();

export const isInfoNode = (node) => {
  if (!node || !node.name) return true;
  const name = String(node.name).trim();
  if (!name) return true;

  if (INFO_PREFIX_RE.test(name)) return true;
  if (INFO_DOMAIN_HINT_RE.test(name)) return true;
  if (INFO_TIMESTAMP_RE.test(name)) return true;
  if (INFO_BALANCE_RE.test(name)) return true;
  if (INFO_WEBSITE_RE.test(name)) return true;

  if (name.startsWith('官网')) {
    return !hasRegionHint(name);
  }

  if (name.includes('官网') && OFFICIAL_URL_RE.test(name) && !hasNodeIdentity(name)) {
    return true;
  }

  if (HARD_INVALID_KEYWORDS.some(keyword => name.includes(keyword))) {
    return true;
  }

  return SOFT_INVALID_KEYWORDS.some(keyword => name.includes(keyword)) && !hasNodeIdentity(name);
};

export const parseNodeTestResponse = (response) => {
  const testPayload = response?.data || {};
  if (testPayload.success === false) {
    const failureMessage = testPayload.error || '节点测试失败';
    const failure = new Error(failureMessage);
    failure.response = { data: { detail: failureMessage } };
    throw failure;
  }
  return testPayload;
};

const NODE_INVALID_REASON_LABELS = {
  'unsupported-reality-option': 'Clash/Mihomo 不支持 Reality spider-x',
  'unsupported-tls-extension': 'Clash/Mihomo 不支持该 TLS 扩展',
  'unsupported-certificate-pin-format': 'Clash/Mihomo 不支持当前证书指纹格式',
  'unsupported-trojan-tcp-disguise': 'Clash/Mihomo 不支持 Trojan TCP HTTP 伪装',
  'unsupported-vless-network': 'Clash/Mihomo 不支持该 VLESS 传输方式',
  'unsupported-vmess-network': 'Clash/Mihomo 不支持该 VMess 传输方式',
  'unsupported-trojan-network': 'Clash/Mihomo 不支持该 Trojan 传输方式',
  'unsupported-anytls-network': 'Clash/Mihomo 不支持该 AnyTLS 传输方式',
  'unsupported-anytls-reality': 'Clash/Mihomo 不支持 AnyTLS Reality',
};

export const getNodeInvalidReasonLabel = (reason) => {
  if (!reason) return '节点配置不兼容';
  return NODE_INVALID_REASON_LABELS[reason] || `节点配置不兼容（${reason}）`;
};

// Latency color helper
export const getLatencyColor = (latency) => {
  if (latency === null || latency === undefined) return 'text-ink-3';
  if (latency < 100) return 'text-green-400';
  if (latency < 200) return 'text-lime-400';
  if (latency < 500) return 'text-yellow-400';
  if (latency < 1000) return 'text-orange-400';
  return 'text-red-400';
};

// Latency status badge
export const getLatencyBadge = (latency, error) => {
  if (error) return { text: '失败', color: 'bg-red-500/20 text-red-400' };
  if (latency === -2) return { text: '失败', color: 'bg-red-500/20 text-red-400' };  // Error
  if (latency === -1) return { text: '超时', color: 'bg-red-500/20 text-red-400' };  // Timeout - red
  if (latency === null) return { text: '超时', color: 'bg-red-500/20 text-red-400' };  // Legacy timeout - red
  if (latency === undefined) return { text: '未测', color: 'bg-ink-3/20 text-ink-2' };
  if (latency < 200) return { text: '优秀', color: 'bg-green-500/20 text-green-400' };
  if (latency < 500) return { text: '良好', color: 'bg-lime-500/20 text-lime-400' };
  if (latency < 1000) return { text: '一般', color: 'bg-yellow-500/20 text-yellow-400' };
  return { text: '较慢', color: 'bg-orange-500/20 text-orange-400' };
};

export const getIpSourceLabel = (source) => ({
  broadcast: '广播 IP',
  native: '原生 IP',
}[source] || '-');

export const getNetworkTypeLabel = (networkType) => ({
  residential: '住宅 IP',
  datacenter: '机房 IP',
}[networkType] || '-');

export const getNodeIpSource = (node) => (
  node?.ip_profile?.ip_source || node?.ip_source || ''
);

export const getNodeIpProperty = (node) => (
  node?.ip_profile?.network_type || node?.network_type || ''
);

export const isNodeIpSourceUntested = (node) => !getNodeIpSource(node);

export const isNodeIpPropertyUntested = (node) => !getNodeIpProperty(node);

export const getNodeCountryFilterValue = (node) => {
  const country = String(node?.country || '').trim();
  const normalizedCountry = country.toUpperCase();
  if (/^[A-Z]{2,3}$/.test(normalizedCountry)) return normalizedCountry;
  return String(node?.region || country).trim();
};

export const getNodeCountryFilterLabel = (node) => {
  const country = String(node?.country || '').trim();
  const normalizedCountry = country.toUpperCase();
  return String(
    node?.region
      || COUNTRY_CHINESE_NAMES[normalizedCountry]
      || country
      || '未知地区'
  ).trim();
};

export const formatRadarRatio = (value) => {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${numeric.toFixed(2)}%` : '-';
};

export const formatIppureScore = (value) => {
  if (value === null || value === undefined || value === '') return '-';
  const normalized = String(value).trim();
  return normalized.endsWith('%') ? normalized : `${normalized}%`;
};

export const mergeIpProfiles = (previous, current) => {
  if (!current || typeof current !== 'object') return previous;
  if (!previous || typeof previous !== 'object') return current;
  return { ...previous, ...current };
};

export const getMetadataStatusLabel = (status, hasValue = false) => {
  if (hasValue) return '';
  if (status === 'success') return '无数据';
  return ({
    no_data: '无数据',
    failed: '检测失败',
    not_configured: '未配置',
    dependency_failed: '依赖数据缺失',
  }[status] || '未检测');
};

export const getMetadataStatusClass = (status, hasValue = false) => {
  if (hasValue) return '';
  if (status === 'failed') return 'text-red-400';
  if (status === 'not_configured') return 'text-amber-400';
  if (status === 'no_data' || status === 'success') return 'text-ink-3';
  return 'text-ink-3';
};
