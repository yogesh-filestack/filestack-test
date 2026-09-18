# filestack-test — FS-12651 egress probe

Answers one question: **is Akamai refusing our fetch because of the User-Agent,
or because of the source IP?**

taskrouter fetches customer URLs from go-utils
`converse/source/resolve.go:makeAndDoRequest`. `www.tui.se` is behind Akamai,
which returned 403 until that function started sending an explicit User-Agent.
The fix works from a developer machine; staging still reported 403. A developer
machine cannot settle that, because it has different egress. **This has to run
on the same egress address as taskrouter.**

## Run

```sh
node asset-proxy.js                 # Node 18+, zero dependencies
PORT=8080 TARGET_URL='https://…' node asset-proxy.js
```

```sh
curl -s localhost:3000/diagnose | jq .answer
```

## Reading the result

`answer.conclusion` is one of:

| conclusion | what it means | what to do |
|---|---|---|
| `UA_IS_SUFFICIENT_HERE` | the deployed UA fetches the asset from this IP; the pre-fix Go default is refused | the header is not the problem here — check that the running binary actually contains the fix: `strings /taskrouter/taskrouter \| grep 'go-utils v'` |
| `EGRESS_IP_BLOCKED` | every profile refused, including ones that pass from a clean machine | no header change can fix it; give `answer.akamaiReference` to TUI and ask for an allowlist, or fetch from a different address |
| `UA_NOT_SUFFICIENT_HERE` | the deployed UA is refused but some other profile passes | diff that profile against what go-utils sends |
| `UA_IRRELEVANT_HERE` | everything passes, pre-fix request included | this host can't reproduce the failure, so it proves nothing — move to the real egress |

`answer.akamaiReference` is the id off Akamai's deny page. TUI can hand it to
Akamai support and get back the exact rule that fired, which settles this
without further guessing.

## Profiles

`gonoua`, `filestack`, `emptyua`, `declaredbot` and `curl` mirror the Go client
exactly — only `Host`, `User-Agent` and `Accept-Encoding: gzip`, because that is
all `net/http` sends. `none`, `ua`, `browser` and `referer` are browser-shaped
controls.

`none` is **not** the pre-fix case: Node omits `User-Agent` entirely, while Go
substitutes `Go-http-client/1.1`. `gonoua` is the real pre-fix request.

## Baseline from a developer machine (2026-09-18)

```
none 403 · ua 403 · browser 200 · referer 200
gonoua 403 · filestack 200 · emptyua 403 · declaredbot 200 · curl 200
```

Three things follow:

1. `gonoua` 403 → `filestack` 200 confirms the FS-12651 fix is correct.
2. `declaredbot` 200 shows nothing about Filestack is allowlisted — it is the
   `<Product>/<version> (+<url>)` declared-crawler shape that passes.
3. `ua` 403 but `browser` 200: a bare Chrome User-Agent is refused, the same one
   with a full browser header set is accepted. Akamai checks that the claimed
   identity matches the rest of the request, so forwarding an end user's
   User-Agent from a service is worse than sending nothing — which is why nginx
   must never pass `$http_user_agent` upstream.

## Caveat

Node core speaks HTTP/1.1; the Go client negotiates HTTP/2 with this origin.
Header-level behaviour matches, but to rule out an HTTP/2- or TLS-fingerprint-
sensitive rule, reproduce with the Go client itself.
