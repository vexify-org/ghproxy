// worker.js
// 私有文件加速下载器：token 鉴权 + 只允许文件下载

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ========== 1. Token 鉴权 ==========
    // 从 Authorization 头读 token，格式：Bearer <token> 或直接 <token>
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();

    // 从环境变量 AUTH_TOKENS 读取，逗号分隔
    const allowedTokens = (env.AUTH_TOKENS || '')
      .split(',')
      .map(t => t.trim())
      .filter(Boolean);

    if (allowedTokens.length > 0 && !allowedTokens.includes(token)) {
      return new Response('Unauthorized: Invalid token', {
        status: 401,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // ========== 2. 解析目标 URL ==========
    // 访问格式：https://domain.top/https://github.com/.../file.zip
    let targetUrl = path.slice(1);
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      return new Response('Bad Request: 路径必须形如 /https://example.com/file.zip', {
        status: 400,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    const target = new URL(targetUrl);

    // ========== 3. 预判：只允许文件下载 ==========
    if (!isFileDownloadRequest(request, target)) {
      return new Response('Forbidden: 只允许下载文件，禁止代理网页', {
        status: 403,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // ========== 4. 构造代理请求 ==========
    const newHeaders = new Headers(request.headers);
    newHeaders.delete('Host');
    newHeaders.delete('Authorization'); // 不把 token 传给目标站
    newHeaders.delete('Cookie');

    const proxyRequest = new Request(targetUrl, {
      method: request.method,
      headers: newHeaders,
      body: request.body,
      redirect: 'follow'
    });

    proxyRequest.headers.set('User-Agent', request.headers.get('User-Agent') || 'Mozilla/5.0');
    proxyRequest.headers.set('Accept', '*/*');

    let response;
    try {
      response = await fetch(proxyRequest, {
        cf: {
          cacheEverything: true,
          cacheTtl: 86400,
          cacheTtlByStatus: { '200-299': 86400, '404': 60, '500-599': 0 }
        }
      });
    } catch (err) {
      return new Response(`Proxy Error: ${err.message}`, { status: 502 });
    }

    // ========== 5. 响应后再次检查：HTML 直接拒绝 ==========
    const contentType = (response.headers.get('Content-Type') || '').toLowerCase();
    if (contentType.includes('text/html') || contentType.includes('application/xhtml+xml')) {
      return new Response('Forbidden: 目标是网页 HTML，已拒绝', {
        status: 403,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // ========== 6. 返回文件，强制下载 ==========
    const responseHeaders = new Headers(response.headers);
    responseHeaders.delete('Content-Security-Policy');
    responseHeaders.delete('X-Frame-Options');
    responseHeaders.delete('Clear-Site-Data');

    if (!responseHeaders.has('Content-Disposition')) {
      responseHeaders.set('Content-Disposition', 'attachment');
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
};

// ========== 辅助函数：判断是不是文件下载请求 ==========
function isFileDownloadRequest(request, target) {
  const path = target.pathname.toLowerCase();

  // 1. 明确禁止网页路径
  if (
    path.endsWith('/') ||
    path.endsWith('.html') ||
    path.endsWith('.htm') ||
    path.endsWith('.php') ||
    path.endsWith('.asp') ||
    path.endsWith('.jsp')
  ) {
    return false;
  }

  // 2. 明确允许的下载路径特征
  if (
    path.includes('/releases/download/') ||
    path.includes('/archive/') ||
    path.includes('/raw/') ||
    path.includes('/codeload/')
  ) {
    return true;
  }

  // 3. 常见文件扩展名
  const fileExtPattern = /\.(zip|tar\.gz|tgz|exe|dmg|pkg|deb|rpm|msi|apk|ipa|whl|jar|war|7z|rar|iso|bin|img|pdf|docx|xlsx|pptx|txt|csv|json|xml|yml|yaml|js|css|wasm|mp4|mkv|mp3|flac|png|jpg|jpeg|gif|webp|svg)$/i;
  if (fileExtPattern.test(path)) {
    return true;
  }

  // 4. Accept 头明确要求二进制
  const accept = (request.headers.get('Accept') || '').toLowerCase();
  if (
    accept.includes('application/octet-stream') ||
    accept.includes('application/zip') ||
    accept.includes('application/gzip') ||
    accept.includes('application/x-tar')
  ) {
    return true;
  }

  return false;
}
