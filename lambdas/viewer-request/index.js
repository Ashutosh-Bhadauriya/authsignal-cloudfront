'use strict';

const querystring = require('querystring');
const { encrypt } = require('../shared/crypto');

exports.handler = async (event) => {
  const request = event.Records[0].cf.request;

  // Preserve the viewer's Host header for downstream Lambda@Edge functions.
  // The AllViewerExceptHostHeader origin request policy replaces it with
  // the origin's host, so we stash the original in a custom header.
  if (request.headers.host && request.headers.host[0]) {
    request.headers['x-forwarded-host'] = [{
      key: 'X-Forwarded-Host',
      value: request.headers.host[0].value,
    }];
  }

  if (request.method !== 'POST' || request.uri !== '/login/password') {
    return request;
  }

  if (!request.body) {
    return request;
  }

  try {
    const body = request.body.encoding === 'base64'
      ? Buffer.from(request.body.data, 'base64').toString('utf8')
      : request.body.data;

    const formData = querystring.parse(body);
    const username = formData.username;

    if (!username) {
      return request;
    }

    const encryptedUsername = encrypt(username);

    if (!request.headers.cookie || request.headers.cookie.length === 0) {
      request.headers.cookie = [{
        key: 'Cookie',
        value: `auth_username=${encryptedUsername}`,
      }];
    } else {
      const existing = request.headers.cookie.map((c) => c.value).join('; ');
      request.headers.cookie = [{
        key: 'Cookie',
        value: `${existing}; auth_username=${encryptedUsername}`,
      }];
    }

    const masked = username.length > 4
      ? `${username.slice(0, 2)}***${username.slice(-2)}`
      : '****';
    console.log(`[viewer-request] Captured username: ${masked}`);
  } catch (err) {
    console.error('[viewer-request] Error:', err.message);
  }

  return request;
};
