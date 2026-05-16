export async function copyToClipboard(text) {
  const value = String(text ?? '');

  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      // Fall back below. Clipboard API can fail on HTTP/non-secure origins or
      // when browser permissions are blocked.
    }
  }

  return fallbackCopyToClipboard(value);
}

function fallbackCopyToClipboard(text) {
  if (typeof document === 'undefined' || !document.body || !document.createElement) {
    return false;
  }

  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute?.('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.top = '-9999px';
  textarea.style.left = '-9999px';
  textarea.style.opacity = '0';

  document.body.appendChild(textarea);
  textarea.focus?.();
  textarea.select?.();

  try {
    return Boolean(document.execCommand?.('copy'));
  } catch {
    return false;
  } finally {
    document.body.removeChild(textarea);
  }
}
