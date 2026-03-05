'use strict';

const { encrypt, decrypt } = require('../shared/crypto');
const { getCookie } = require('../shared/cookies');
const { httpsRequest } = require('../shared/http');
const { AUTHSIGNAL_API_HOST, AUTHSIGNAL_API_SECRET } = require('../shared/config');

const AUTH_HEADER = 'Basic ' + Buffer.from(AUTHSIGNAL_API_SECRET + ':').toString('base64');

exports.handler = async (event) => {
  const request = event.Records[0].cf.request;
  const response = event.Records[0].cf.response;

  if (request.method !== 'POST' || request.uri !== '/login/password' || response.status !== '302') {
    return response;
  }

  try {
    const encryptedUsername = getCookie(request.headers.cookie, 'auth_username');
    if (!encryptedUsername) {
      console.log('[origin-response] No auth_username cookie, skipping risk check');
      return response;
    }

    const userId = decrypt(encryptedUsername);
    if (!userId) return response;

    const masked = userId.length > 4
      ? `${userId.slice(0, 2)}***${userId.slice(-2)}`
      : '****';
    console.log(`[origin-response] Evaluating risk for: ${masked}`);

    const custom = {};
    for (const key of Object.keys(request.headers)) {
      if (key.startsWith('x-amzn-waf-')) {
        custom[key.replace(/-/g, '_')] = request.headers[key][0].value;
      }
    }

    const host = request.headers['x-forwarded-host']
      ? request.headers['x-forwarded-host'][0].value
      : (request.headers.host ? request.headers.host[0].value : '');
    const userAgent = request.headers['user-agent']
      ? request.headers['user-agent'][0].value
      : '';

    const requestBody = JSON.stringify({
      redirectUrl: `https://${host}/login/password`,
      ipAddress: request.clientIp,
      userAgent,
      custom: Object.keys(custom).length > 0 ? custom : undefined,
    });

    const apiResponse = await httpsRequest({
      hostname: AUTHSIGNAL_API_HOST,
      path: `/v1/users/${encodeURIComponent(userId)}/actions/signIn`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(requestBody),
        'Authorization': AUTH_HEADER,
      },
    }, requestBody);

    console.log(`[origin-response] AuthSignal state: ${apiResponse.body.state}`);

    if (apiResponse.body.state === 'ALLOW') {
      if (!response.headers['set-cookie']) {
        response.headers['set-cookie'] = [];
      }
      response.headers['set-cookie'].push({
        key: 'Set-Cookie',
        value: 'auth_username=; Path=/; Secure; HttpOnly; Max-Age=0',
      });
      return response;
    }

    if (apiResponse.body.state === 'CHALLENGE_REQUIRED') {
      const sessionCookies = response.headers['set-cookie'] || [];
      const originalLocation = response.headers.location
        ? response.headers.location[0].value
        : '/';

      const challengeData = JSON.stringify({
        userId,
        idempotencyKey: apiResponse.body.idempotencyKey,
        originalLocation,
        sessionCookies,
      });

      const encryptedChallenge = encrypt(challengeData);

      return {
        status: '302',
        statusDescription: 'Found',
        headers: {
          location: [{ key: 'Location', value: apiResponse.body.url }],
          'set-cookie': [
            {
              key: 'Set-Cookie',
              value: `auth_challenge=${encryptedChallenge}; Secure; HttpOnly; Path=/; SameSite=Lax`,
            },
            {
              key: 'Set-Cookie',
              value: 'auth_username=; Path=/; Secure; HttpOnly; Max-Age=0',
            },
          ],
          'cache-control': [{
            key: 'Cache-Control',
            value: 'no-cache, no-store, must-revalidate',
          }],
        },
      };
    }

    // BLOCK or unknown state — clean up and pass through
    if (!response.headers['set-cookie']) {
      response.headers['set-cookie'] = [];
    }
    response.headers['set-cookie'].push({
      key: 'Set-Cookie',
      value: 'auth_username=; Path=/; Secure; HttpOnly; Max-Age=0',
    });
    return response;
  } catch (err) {
    console.error('[origin-response] Error:', err.message);
    return response;
  }
};
