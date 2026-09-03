/** Build browser URLs relative to the plugin iframe rather than the dashboard root. */
export function pluginRelativePath(path: string): string {
  return `./${path.replace(/^\/+/, '')}`;
}

export function pluginWebSocketUrl(path: string): string {
  const url = new URL(pluginRelativePath(path), window.location.href);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.toString();
}
