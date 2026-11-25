export function toDate(isoString) {
  if (!isoString) return null;
  if (isoString instanceof Date) return isNaN(isoString.getTime()) ? null : isoString;
  let str = String(isoString).trim().replace(' ', 'T');
  if (!str.endsWith('Z') && !str.includes('+') && str.length >= 19) {
    str = str + 'Z';
  }
  const date = new Date(str);
  return isNaN(date.getTime()) ? null : date;
}

export function formatLocalTime(isoString) {
  const date = toDate(isoString);
  if (!date) return isoString || '';
  return new Intl.DateTimeFormat('en-US', {
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  }).format(date);
}

export function formatLocalDate(isoString) {
  const date = toDate(isoString);
  if (!date) return isoString || '';
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  }).format(date);
}

export function formatChartBucket(key) {
  if (!key) return '';
  const str = String(key).trim();
  let iso = str;
  if (/^\d{4}-\d{2}-\d{2}$/.test(str)) {
    iso = `${str}T00:00:00Z`;
  } else if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(str)) {
    iso = `${str.replace(' ', 'T')}:00Z`;
  }
  const date = new Date(iso);
  if (isNaN(date.getTime())) return str;
  return new Intl.DateTimeFormat('en-US', {
    ...(str.length <= 10
      ? { month: 'short', day: 'numeric' }
      : { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true }),
  }).format(date);
}

export function formatRelative(isoString, now = Date.now()) {
  const date = toDate(isoString);
  if (!date) return 'never';
  const secs = Math.max(0, Math.floor((now - date.getTime()) / 1000));
  if (secs < 60) return 'just now';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}