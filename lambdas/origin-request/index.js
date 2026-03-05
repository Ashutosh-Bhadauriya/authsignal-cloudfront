'use strict';

const querystring = require('querystring');
const { decrypt } = require('../shared/crypto');
const { getCookie } = require('../shared/cookies');
const { httpsRequest } = require('../shared/http');
const { AUTHSIGNAL_API_HOST, AUTHSIGNAL_API_SECRET } = require('../shared/config');

const AUTH_HEADER = 'Basic ' + Buffer.from(AUTHSIGNAL_API_SECRET + ':').toString('base64');

function errorResponse(status, statusDescription, body) {
  return {
    status: String(status),
    statusDescription,
    headers: {
      'content-type': [{ key: 'Content-Type', value: 'text/html' }],
      'set-cookie': [{
        key: 'Set-Cookie',
        value: 'auth_challenge=; Secure; HttpOnly; Path=/; Max-Age=0',
      }],
      'cache-control': [{
        key: 'Cache-Control',
        value: 'no-cache, no-store, must-revalidate',
      }],
    },
    body,
  };
}

exports.handler = async (event) => {
  const request = event.Records[0].cf.request;

  if (request.method !== 'GET' || request.uri !== '/login/password') {
    return request;
  }

  const queryParams = querystring.parse(request.querystring);
  const token = queryParams.token;

  if (!token || !request.headers.cookie) {
    return request;
  }

  const authChallengeCookie = getCookie(request.headers.cookie, 'auth_challenge');
  if (!authChallengeCookie) {
    return request;
  }

  try {
    const cookieData = JSON.parse(decrypt(authChallengeCookie));

    console.log(`[origin-request] Validating challenge for user: ${cookieData.userId}`);

    const requestBody = JSON.stringify({ token });

    const validateResponse = await httpsRequest({
      hostname: AUTHSIGNAL_API_HOST,
      path: '/v1/validate',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(requestBody),
        'Authorization': AUTH_HEADER,
      },
    }, requestBody);

    const stateOk = validateResponse.body.state === 'CHALLENGE_SUCCEEDED';
    const idempotencyOk = validateResponse.body.idempotencyKey === cookieData.idempotencyKey;
    const userIdOk = validateResponse.body.userId === cookieData.userId;

    console.log(`[origin-request] Validation: state=${stateOk} idempotency=${idempotencyOk} userId=${userIdOk}`);

    if (stateOk && idempotencyOk && userIdOk) {
      const response = {
        status: '302',
        statusDescription: 'Found',
        headers: {
          location: [{
            key: 'Location',
            value: cookieData.originalLocation || '/',
          }],
          'set-cookie': [
            {
              key: 'Set-Cookie',
              value: 'auth_challenge=; Secure; HttpOnly; Path=/; Max-Age=0',
            },
          ],
          'cache-control': [{
            key: 'Cache-Control',
            value: 'no-cache, no-store, must-revalidate',
          }],
        },
      };

      if (Array.isArray(cookieData.sessionCookies)) {
        for (const cookie of cookieData.sessionCookies) {
          response.headers['set-cookie'].push(cookie);
        }
      }

      console.log('[origin-request] Challenge succeeded, restoring session');
      return response;
    }

    console.log('[origin-request] Challenge validation failed');
    return errorResponse(403, 'Forbidden',
      '<html><body><h1>Authentication Failed</h1><p>The security challenge was not completed successfully.</p><a href="/">Try again</a></body></html>'
    );
  } catch (err) {
    console.error('[origin-request] Error:', err.message);
    return errorResponse(500, 'Internal Server Error',
      '<html><body><h1>Error</h1><p>An unexpected error occurred.</p><a href="/">Try again</a></body></html>'
    );
  }
};
