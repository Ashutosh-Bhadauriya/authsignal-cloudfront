# AuthSignal Adaptive MFA Demo - Lambda@Edge

A demo app showing how AuthSignal intercepts login requests at the CloudFront edge
to add adaptive multi-factor authentication — without modifying the origin application.

## How It Works

```
User → CloudFront → Lambda@Edge (risk check) → AuthSignal MFA → Session restored
```

1. User submits login credentials on the demo app
2. **Viewer Request** Lambda captures the username and encrypts it into a cookie
3. The origin app processes the login normally (sets session cookie, returns 302)
4. **Origin Response** Lambda intercepts the 302, calls AuthSignal to evaluate risk
   - **Low risk:** login proceeds normally
   - **Elevated risk:** user is redirected to complete an MFA challenge
5. After completing MFA, the user is redirected back with a token
6. **Origin Request** Lambda validates the token, restores the original session, and redirects to the dashboard

## Prerequisites

- **AWS Account** - with admin access
- **AWS CLI** - [Install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **AWS SAM CLI** - [Install guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- **Node.js 20+** - [Download](https://nodejs.org/)
- **AuthSignal Account** - [Sign up free](https://portal.authsignal.com)

## Setup

### 1. Configure AWS CLI

If you haven't already, configure your AWS credentials:

```bash
aws configure
```

Enter your Access Key ID, Secret Access Key, and set the region to `us-east-1`.

### 2. Get Your AuthSignal API Secret

1. Go to [portal.authsignal.com](https://portal.authsignal.com)
2. Navigate to **Settings → API Keys**
3. Copy your **API Secret**

### 3. Generate Encryption Keys

Run these commands to generate secure keys:

```bash
# Generate encryption key (copy the output)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate initialization vector (copy the output)
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
```

### 4. Update Configuration

Copy the example config and replace the placeholder values:

```bash
cp lambdas/shared/config.example.js lambdas/shared/config.js
```

Then edit `lambdas/shared/config.js`:

```js
const AUTHSIGNAL_API_SECRET = 'your-actual-api-secret';
const ENCRYPTION_KEY = 'your-64-char-hex-key';
const ENCRYPTION_IV  = 'your-32-char-hex-iv';
```

### 5. Install Origin App Dependencies

```bash
cd origin-app
npm install
cd ..
```

## Deploy

Everything deploys with two commands. **You must deploy to us-east-1** (required for Lambda@Edge).

```bash
sam build

sam deploy --guided --region us-east-1
```

SAM will ask you a few questions:

- **Stack Name:** `authsignal-mfa-demo`
- **AWS Region:** `us-east-1` (required)
- **Confirm changes before deploy:** `y`
- **Allow SAM CLI IAM role creation:** `y`
- **Everything else:** press Enter for defaults

Wait for the deployment to complete (CloudFront distributions take 5-10 minutes).

When done, SAM will print the outputs:

```
CloudFrontUrl = https://d1234567890.cloudfront.net
ApiUrl        = https://abc123.execute-api.us-east-1.amazonaws.com
```

## Test the Demo

1. Open the **CloudFrontUrl** in your browser
2. Enter any username and password
3. Depending on the AuthSignal risk assessment:
   - **Low risk:** you'll go straight to the dashboard
   - **Elevated risk:** you'll be redirected to complete MFA, then land on the dashboard

To test the MFA flow, configure a rule in the AuthSignal portal:
1. Go to **Actions → signIn** (create it if it doesn't exist)
2. Add a rule that returns **CHALLENGE** (e.g., challenge all sign-ins for testing)
3. Set up an authenticator (e.g., email OTP, TOTP, passkey)

## Testing Locally (Origin Only)

You can run the origin app locally to test the login UI without Lambda@Edge:

```bash
cd origin-app
npm install
node index.js
```

Open http://localhost:3000 — this bypasses the Lambda@Edge functions (no MFA).

## Project Structure

```
authsignal-aws/
├── template.yaml                  # SAM deployment template
├── origin-app/
│   ├── package.json
│   └── index.js                   # Demo login app (Express.js)
└── lambdas/
    ├── shared/
    │   ├── config.example.js      # Template (copy to config.js)
    │   ├── config.js              # API keys and encryption (gitignored)
    │   ├── crypto.js              # AES-256-CBC encrypt/decrypt
    │   ├── cookies.js             # Cookie parsing helpers
    │   └── http.js                # HTTPS request helper
    ├── viewer-request/
    │   └── index.js               # Captures username on login POST
    ├── origin-response/
    │   └── index.js               # Calls AuthSignal, redirects for MFA if needed
    └── origin-request/
        └── index.js               # Validates MFA token, restores session
```

## Cleanup

To delete all resources:

```bash
sam delete --stack-name authsignal-mfa-demo --region us-east-1
```
