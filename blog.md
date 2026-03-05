# Add adaptive MFA to any web app with Authsignal and Lambda@Edge

Most MFA guides assume you control the backend. This one doesn't.

Adding multi-factor authentication to an existing web application typically means touching the backend: new routes, session state, SDK integrations, and a flag day where everything has to land together. With AWS Lambda@Edge and Authsignal, you can bolt on adaptive, risk-based MFA at the CloudFront layer without changing a single line of your origin application's code.

This guide covers a full working implementation: three Lambda@Edge functions that intercept the login flow, call Authsignal for risk evaluation, and conditionally enforce MFA challenges — transparently, from the edge.

## Prerequisites

- **AWS account** with permissions to create Lambda functions and CloudFront distributions
- **AWS SAM CLI** — [install guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- **Authsignal account** — [sign up](https://portal.authsignal.com). Retrieve your API secret from Settings > API Keys.

## How it works

Three Lambda@Edge functions attach to a CloudFront distribution. Each runs at a different stage of the request lifecycle. Walking through each step:

1. User submits email and password via a standard login form.
2. **Viewer request** intercepts the POST, extracts the username, encrypts it, and stores it in a cookie.
3. The origin processes the login normally: validates credentials, sets a session cookie, returns a 302 redirect.
4. **Origin response** intercepts the 302, decrypts the username, and calls the Authsignal API to evaluate risk.
5. If `ALLOW`: the response passes through unchanged.
6. If `CHALLENGE_REQUIRED`: the function preserves the original session state in an encrypted cookie and redirects to Authsignal's MFA page.
7. After the user completes the challenge, Authsignal redirects back with a token.
8. **Origin request** intercepts the callback, validates the token, verifies the user and idempotency key, restores the original session cookies, and redirects to the dashboard.

The origin application is never touched.

One thing worth noting before diving into the code: Lambda@Edge functions can't use environment variables, and they can't share in-memory state — each function runs independently at the edge. The only channel for passing state between them is cookies. That's why there's an encryption layer: all sensitive state (usernames, session cookies, challenge metadata) gets encrypted before it goes into a cookie, and decrypted on the other side.

## Step 1: Shared utilities

Lambda@Edge functions cannot use environment variables. Configuration is hardcoded in `lambdas/shared/config.js`:

```javascript
'use strict';

const AUTHSIGNAL_API_SECRET = 'YOUR_AUTHSIGNAL_SECRET_HERE';
const AUTHSIGNAL_API_HOST = 'api.authsignal.com';

// Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const ENCRYPTION_KEY = 'YOUR_64_HEX_CHAR_KEY_HERE';

// Generate with: node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
const ENCRYPTION_IV = 'YOUR_32_HEX_CHAR_IV_HERE';

module.exports = {
  AUTHSIGNAL_API_SECRET,
  AUTHSIGNAL_API_HOST,
  ENCRYPTION_KEY,
  ENCRYPTION_IV,
};
```

Replace the placeholders with your Authsignal secret and generated encryption keys before deploying.

Encryption helpers in `lambdas/shared/crypto.js`:

```javascript
'use strict';

const crypto = require('crypto');
const { ENCRYPTION_KEY, ENCRYPTION_IV } = require('./config');

const ALGORITHM = 'aes-256-cbc';
const key = Buffer.from(ENCRYPTION_KEY, 'hex');
const iv = Buffer.from(ENCRYPTION_IV, 'hex');

function encrypt(text) {
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encodeURIComponent(encrypted);
}

function decrypt(encoded) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  let decrypted = decipher.update(decodeURIComponent(encoded), 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encrypt, decrypt };
```

Output is URL-encoded so it's safe to drop directly into a cookie value.

Cookie parser for CloudFront's header format in `lambdas/shared/cookies.js`:

```javascript
'use strict';

function getCookie(cookieHeaders, name) {
  if (!cookieHeaders) return null;

  for (const header of cookieHeaders) {
    const value = header.value || '';
    const pairs = value.split(';');
    for (const pair of pairs) {
      const [key, ...rest] = pair.trim().split('=');
      if (key && key.trim() === name) {
        return rest.join('=').trim();
      }
    }
  }

  return null;
}

module.exports = { getCookie };
```

CloudFront headers are arrays of `{ key, value }` objects rather than plain strings. `rest.join('=')` handles cookie values that themselves contain `=` characters, which is common with base64-encoded data.

HTTPS request helper in `lambdas/shared/http.js`. Lambda@Edge doesn't support external npm dependencies at the edge, so this uses Node's built-in `https` module:

```javascript
'use strict';

const https = require('https');

function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
        } catch (_) {
          resolve({ statusCode: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

module.exports = { httpsRequest };
```

## Step 2: Viewer request function

This function fires on every incoming request before it reaches the origin. For login POSTs, it extracts the username from the form body and stashes it in an encrypted cookie so the origin response function can use it later.

`lambdas/viewer-request/index.js`:

```javascript
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
```

Two things worth calling out here. First, `X-Forwarded-Host` is set on every request, not just login POSTs. This is because CloudFront's `AllViewerExceptHostHeader` policy (used in the SAM template) replaces the viewer's Host header with the origin domain. Without preserving the original, the origin response function can't build a correct redirect URL for Authsignal. Second, POST body encoding isn't guaranteed: CloudFront can deliver it as plain text or base64 depending on the content, so both cases need handling.

## Step 3: Origin response function

This is where the actual risk decision happens. It intercepts successful login responses (302 from `POST /login/password`), calls Authsignal with the user's IP and context, and either lets the response through or swaps it for a redirect to MFA.

`lambdas/origin-response/index.js`:

```javascript
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
```

When Authsignal returns `ALLOW`, the original 302 passes through as-is and the temporary username cookie gets cleared. Clean exit.

When it returns `CHALLENGE_REQUIRED`, the function does something important: it saves the origin's session cookies (the ones the origin just set on the 302) into the encrypted `auth_challenge` cookie, along with the redirect destination and idempotency key. Then it builds a new 302 that sends the user to Authsignal's MFA page instead. The `redirectUrl` in the API call is set to `/login/password` so Authsignal knows where to send the user back after they complete the challenge.

## Step 4: Origin request function

This function handles the return leg after MFA. Authsignal redirects back to `/login/password?token=...`, and this function intercepts that GET request, validates the token, and restores the session.

`lambdas/origin-request/index.js`:

```javascript
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
```

Three checks must all pass before the session is restored: the challenge state must be `CHALLENGE_SUCCEEDED`, the idempotency key must match what was stored in the cookie (preventing replay attacks), and the userId must be the same person who initiated the login. If any of them fail, the user gets a 403 and the challenge cookie is cleared.

On success, the function builds a 302 that sets all the session cookies saved earlier (from the origin's original response) and sends the user to their original destination. From the user's perspective, it's just a login.

## Step 5: Demo origin app

The demo uses a minimal Express.js app as the origin. It accepts any email/password combination and sets a session cookie. This is intentionally stripped down so it's easy to see the boundary between the origin and the edge logic. In production, you'd point the CloudFront distribution at your existing login application and remove this entirely.

Key routes in `origin-app/index.js`:

```javascript
app.post('/login/password', (req, res) => {
  const { username } = req.body;

  res.cookie('session', username, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 3600000,
  });
  res.redirect('/dashboard');
});

app.get('/dashboard', (req, res) => {
  const username = req.cookies.session;
  if (!username) {
    return res.redirect('/');
  }
  // render dashboard
});
```

The app is wrapped with `@vendia/serverless-express` to run as a Lambda behind API Gateway. It has no knowledge of Authsignal, MFA, or anything the edge functions are doing.

## Step 6: SAM template

The template creates everything: the origin Lambda and API Gateway, the three Lambda@Edge functions, IAM roles, and the CloudFront distribution. Four things in the config are worth paying attention to:

`template.yaml`:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  Authsignal Adaptive MFA — CloudFront + Lambda@Edge.
  MUST be deployed to us-east-1 (required for Lambda@Edge).

Globals:
  Function:
    Runtime: nodejs20.x

Resources:
  OriginFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: origin-app/
      Handler: index.handler
      MemorySize: 256
      Timeout: 30
      Events:
        RootGet:
          Type: HttpApi
        ProxyAll:
          Type: HttpApi
          Properties:
            Path: /{proxy+}
            Method: ANY

  EdgeLambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - edgelambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

  ViewerRequestFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: lambdas/
      Handler: viewer-request/index.handler
      MemorySize: 128
      Timeout: 5
      Role: !GetAtt EdgeLambdaRole.Arn
      AutoPublishAlias: live

  OriginResponseFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: lambdas/
      Handler: origin-response/index.handler
      MemorySize: 128
      Timeout: 30
      Role: !GetAtt EdgeLambdaRole.Arn
      AutoPublishAlias: live

  OriginRequestFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: lambdas/
      Handler: origin-request/index.handler
      MemorySize: 128
      Timeout: 30
      Role: !GetAtt EdgeLambdaRole.Arn
      AutoPublishAlias: live

  Distribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        HttpVersion: http2
        DefaultCacheBehavior:
          TargetOriginId: OriginApi
          ViewerProtocolPolicy: redirect-to-https
          AllowedMethods: [GET, HEAD, OPTIONS, PUT, PATCH, POST, DELETE]
          CachedMethods: [GET, HEAD]
          CachePolicyId: 4135ea2d-6df8-44a3-9df3-4b5a84be39ad
          OriginRequestPolicyId: b689b0a8-53d0-40ab-baf2-68738e2966ac
          LambdaFunctionAssociations:
            - EventType: viewer-request
              LambdaFunctionARN: !Ref ViewerRequestFunction.Version
              IncludeBody: true
            - EventType: origin-request
              LambdaFunctionARN: !Ref OriginRequestFunction.Version
            - EventType: origin-response
              LambdaFunctionARN: !Ref OriginResponseFunction.Version
        Origins:
          - Id: OriginApi
            DomainName: !Sub "${ServerlessHttpApi}.execute-api.${AWS::Region}.amazonaws.com"
            CustomOriginConfig:
              HTTPSPort: 443
              OriginProtocolPolicy: https-only

Outputs:
  CloudFrontUrl:
    Value: !Sub "https://${Distribution.DomainName}"
  ApiUrl:
    Value: !Sub "https://${ServerlessHttpApi}.execute-api.${AWS::Region}.amazonaws.com"
```

The four things that matter here:

- **`EdgeLambdaRole`** needs to trust both `lambda.amazonaws.com` and `edgelambda.amazonaws.com`. Miss one and deployment fails.
- **`AutoPublishAlias: live`** creates a new versioned ARN on every deploy and wires it to CloudFront automatically. Lambda@Edge requires versioned functions, not `$LATEST`.
- **`IncludeBody: true`** on the viewer request association is what lets the function read the POST body. Without it, `event.Records[0].cf.request.body` is empty.
- **`CachePolicyId: 4135ea2d-...`** is the AWS-managed `CachingDisabled` policy. Login flows must never be cached.

## Step 7: Deploy and test

Install dependencies:

```bash
cd origin-app && npm install && cd ..
```

Ensure `lambdas/package.json` exists with CommonJS mode (Lambda@Edge requires it):

```json
{
  "name": "authsignal-lambdas",
  "version": "1.0.0",
  "private": true,
  "type": "commonjs"
}
```

Build and deploy to `us-east-1` (Lambda@Edge functions must live in us-east-1 regardless of where your users are):

```bash
sam build
sam deploy --guided --region us-east-1
```

SAM will prompt for a stack name and confirm IAM role creation. The CloudFront distribution takes 5-10 minutes to provision. The CloudFront URL appears in the stack outputs once it's ready.

### Configuring Authsignal rules

By default, Authsignal returns `ALLOW` for all sign-ins. To trigger MFA:

1. Open [portal.authsignal.com](https://portal.authsignal.com)
2. Navigate to **Actions** and find or create the **signIn** action
3. Add a rule that returns **Challenge** (for testing, challenge all sign-ins)
4. Enable at least one verification method (email OTP, passkey, or TOTP)

Sign in through the CloudFront URL. You'll be redirected to Authsignal's challenge page. Complete verification, and you land on the dashboard with your session intact. The origin app saw none of it.

The full source code is available in the [authsignal-aws](https://github.com/authsignal/authsignal-aws) repository.