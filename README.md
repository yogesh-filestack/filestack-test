# resolve-probe — FS-12651

Sends the **exact** request taskrouter sends when it resolves an external URL,
so the 403 can be observed from any host.

## Why it is identical

`makeAndDoRequest` in [`main.go`](main.go) is copied from go-utils
`converse/source/resolve.go` as deployed
(`v1.25.1-0.20260917061700-1859b276a5b0`). Same `http.Client` with **no custom
`Transport`**, same `CheckRedirect`, same `httptrace` cancel-after-two-writes
HTTP/2 logic, same HTTP/1.1 fallback, same `req.Header.Set("User-Agent", …)`
placed before the `Source.Headers` loop. Three deviations, each marked `PROBE:`
and nothing more.

Everything around the request is matched too:

| | taskrouter | this probe |
|---|---|---|
| toolchain | `golang:1.19` (`build/ci/Dockerfile.jenkins`) | `golang:1.19` ([`Dockerfile`](Dockerfile)) |
| runtime image | `alpine:3.14` + `ca-certificates` | same |
| URL passed in | `src.URLExternal.String()` | parsed and re-serialised the same way |
| `Source.Headers` | nil for a plain URL request | nil |

That makes the bytes on the wire the same:

```
:authority: www.tui.se
:method: GET
:path: /cdn/media/sys_master/h07/h51/15866047922206/740-425-RIU-TUI-walk-to-beach.jpg
:scheme: https
user-agent: Filestack-Processing-Engine/1.0 (+https://www.filestack.com)
accept-encoding: gzip
```

`accept-encoding: gzip` is added by `net/http` itself, in both.

**The one thing this cannot copy is the source IP.** Akamai demonstrably applies
different policies to different sources (see Results), so a run only tells you
about the host it ran on. To learn anything about staging, run it from
staging's egress address.

## Endpoints

| endpoint | what it does |
|---|---|
| `GET /diagnose` | every variant in sequence, plus a verdict — start here |
| `GET /fetch?variant=fixed` | one attempt, full detail |
| `GET /image` | performs the deployed request and streams the origin's answer back verbatim — the JPEG on 200, Akamai's deny page on 403. **Open this in a browser.** |
| `GET /health` | liveness, plus the Go toolchain actually in the binary |

Both `/diagnose` and `/fetch` accept `?url=…`.

Every result carries `sentHeaders`, captured with `httptrace.WroteHeaderField`
— what actually went on the wire, not what was intended.

### Variants

| variant | reproduces |
|---|---|
| `fixed` | go-utils as deployed today |
| `prefix` | go-utils **before** FS-12651 — `net/http` supplies its own agent |
| `empty` | `User-Agent` set to `""` |
| `browser` | a forwarded end user Chrome agent |
| `declaredbot` | same `(+url)` shape, unrelated brand |
| `caller-override` | the fix, then `Source.Headers` overwrites it in the loop |

## Run

```sh
docker build -t resolve-probe . && docker run --rm -p 3000:3000 resolve-probe
curl -s localhost:3000/diagnose | jq
open http://localhost:3000/image
```

Use Docker rather than `go run` — a local toolchain is not 1.19, and `/health`
will tell you so.

## Deploy on Render

Commit [`render.yaml`](render.yaml) and use **New → Blueprint**, or create a
**New → Web Service** with **Runtime: Docker**.

Do **not** use Render's native Go runtime. `GO_VERSION` is advisory there and was
ignored — the first deploy built with 1.27.1. The Dockerfile pins 1.19.

```sh
curl -s https://<service>.onrender.com/diagnose | jq .answer
```

## Reading `answer`

| verdict | meaning | next step |
|---|---|---|
| `UA_IS_SUFFICIENT_HERE` | deployed UA works here, pre-fix refused | the header is fine *on this host*; verify the binary: `strings /taskrouter/taskrouter \| grep 'go-utils v'` |
| `EGRESS_IP_BLOCKED` | every variant refused | no header fixes it; send `akamaiReference` to TUI |
| `UA_NOT_SUFFICIENT_HERE` | deployed UA refused, another variant passes | diff that variant against what go-utils sends |
| `UA_IRRELEVANT_HERE` | everything passes, pre-fix included | can't reproduce here; run from taskrouter's egress |

`akamaiReference` comes off Akamai's deny page. TUI can give it to Akamai support
and get back the exact rule that fired.

Non-200 results carry `taskrouterError`, verbatim from `ResolveExternal`, so they
line up with the taskrouter log.

## Results

| variant | laptop, go1.19 | laptop, go1.25.4 | Render, go1.27.1 |
|---|---|---|---|
| `fixed` | 200 | 200 | 200 |
| `prefix` | **403** | **403** | **403** |
| `empty` | 403 | 403 | 200 |
| `browser` | 403 | 403 | 200 |
| `declaredbot` | 200 | 200 | 200 |
| `caller-override` | 403 | 403 | 200 |

**The Go version changes nothing.** 1.19 and 1.25.4 give identical results from
the same host, so the TLS ClientHello is not what Akamai is reacting to.

**The source does change things.** A blank or browser agent is refused from the
laptop and accepted from Render. Akamai applies different policies to different
sources, which is why no run here can stand in for staging.

**`prefix` fails everywhere and `fixed` works everywhere.** That is the only
invariant across all three runs.

**`empty` vs `prefix` is a controlled experiment.** On Render those two requests
are byte-identical except that `prefix` carries `user-agent: Go-http-client/2.0`
and `empty` carries no agent at all — 200 and 403 respectively. Akamai is
matching that literal token.

### Two incidental findings

1. Over HTTP/2 the default agent is `Go-http-client/**2.0**`, not `1.1`.
2. `Header.Set("User-Agent", "")` puts **no header on the wire** in Go.

### One real bug

`caller-override` shows the `for key, value := range headers` loop running
*after* the fix, so a `User-Agent` in `Source.Headers` silently replaces it —
reachable through the extended-source form `{"url": …, "headers": {…}}`. It is
refused from the laptop, so under a stricter policy a customer can still trigger
the original failure.
