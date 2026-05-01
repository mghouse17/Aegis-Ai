# GitHub App Setup

This document describes how to register and configure the GitHub App used by
Aegis AI to receive pull request webhook events and authenticate to GitHub.

## 1. Create the GitHub App

Create a GitHub App from your GitHub account or organization settings.

Use a clear app name, for example:

```text
Aegis AI
```

Set the homepage URL to the deployed application URL when available. For local
development, use your repository URL or a temporary local tunnel URL.

## 2. Configure Repository Permissions

Configure the GitHub App with the minimum repository permissions needed by the
backend.

| Permission | Access | Why it is needed |
| --- | --- | --- |
| Pull requests | Read | Receive and inspect pull request metadata and webhook events. |
| Contents | Read | Read repository files and pull request diff contents when analysis is performed. |
| Commit statuses | Read and write | Publish analysis status back to commits. |

Do not grant broader permissions unless a new backend feature explicitly needs
them.

## 3. Configure Webhook

Enable webhooks for the app.

Set the webhook URL to:

```text
https://<your-domain>/webhooks/github/pr
```

For local development, expose the backend with a tunnel and use that public URL:

```text
https://<your-tunnel-domain>/webhooks/github/pr
```

Set the content type to:

```text
application/json
```

Set a strong webhook secret. This value must match the backend
`GITHUB_WEBHOOK_SECRET` environment variable.

Subscribe to these events:

```text
Pull request
```

The backend currently accepts only these pull request actions:

```text
opened
synchronize
reopened
```

Other GitHub events and unsupported pull request actions are ignored after
signature verification.

## 4. Generate and Store Credentials

After creating the app, generate a private key from the GitHub App settings.

Store secrets outside source control. Never commit real GitHub App IDs, private
keys, installation tokens, access tokens, or webhook secrets.

Required backend environment variables:

```env
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=replace-with-a-strong-secret
```

For local development, copy `backend/.env.example` to your local environment
manager or shell. Do not commit a real `.env` file.

The backend reads:

- `GITHUB_APP_ID` and `GITHUB_PRIVATE_KEY` in `backend/app/integrations/github/auth.py`
- `GITHUB_WEBHOOK_SECRET` in `backend/app/integrations/github/webhook.py`

Secrets must not be logged. If you add logging around GitHub authentication or
webhook handling, log only stable metadata such as event type, delivery ID,
repository ID, pull request number, or retry count.

## 5. Install the App

Install the GitHub App on the repositories or organization that Aegis AI should
analyze.

Prefer selecting only the repositories that need analysis instead of granting
access to every repository by default.

## 6. Backend Behavior

The webhook endpoint is:

```text
POST /webhooks/github/pr
```

The endpoint:

- Rejects missing, malformed, or invalid `X-Hub-Signature-256` headers.
- Verifies the signature against the exact raw request body.
- Rejects oversized payloads.
- Ignores non-`pull_request` events.
- Accepts only `opened`, `synchronize`, and `reopened` pull request actions.
- Parses accepted payloads into a typed pull request event model.
- Tracks delivery IDs through an injectable delivery tracker interface.

The GitHub API client detects rate limits and retries with exponential backoff
and jitter.

## 7. Verify Locally

Run the focused backend webhook tests:

```bash
cd backend
pytest app/tests
```

Expected result:

```text
33 passed
```

These tests cover:

- Accepted pull request actions: `opened`, `synchronize`, `reopened`.
- Ignored events and ignored unsupported pull request actions.
- Missing and invalid webhook signatures.
- Malformed JSON payloads.
- Missing required payload fields.
- Oversized request bodies.

## 8. Production Notes

Before production deployment:

- Replace the default no-op delivery tracker with a persistent atomic
  check-and-set implementation, such as Redis `SETNX` with TTL or a database
  insert with conflict handling.
- Store secrets in a production secret manager or encrypted deployment
  environment, not in plaintext files.
- Rotate the webhook secret if it is exposed.
- Rotate the GitHub App private key if it is exposed.
- Add tests for GitHub API rate limit retry behavior if the client becomes part
  of a critical processing path.
