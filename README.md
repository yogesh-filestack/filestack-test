# resolve-probe — FS-12651

Reproduces the **exact** request go-utils makes to an external URL, so the 403
can be observed from an arbitrary host.

`makeAndDoRequest` in [`main.go`](main.go) is copied from go-utils
`converse/source/resolve.go` as deployed
(`v1.25.1-0.20260917061700-1859b276a5b0`): same `http.Client` with no custom
`Transport`, same `CheckRedirect`, same `httptrace` HTTP/2 cancel-after-2-writes
logic, same HTTP/1.1 fallback, same `req.Header.Set("User-Agent", …)` before the
`Source.Headers` loop. Three deviations, each marked `PROBE:` in the source and
nothing else.

nginx is not involved. This is the first request out of the Go process.

## Endpoints

| endpoint | what it does |
|---|---|
| `GET /health` | liveness, plus the Go toolchain the binary was built with |
| `GET /fetch?variant=fixed` | one attempt, full detail |
| `GET /diagnose` | every variant in sequence, plus a verdict |

Both accept `?url=…` to override the target.

### Variants

| variant | what it reproduces |
|---|---|
| `fixed` | go-utils as deployed today |
| `prefix` | go-utils **before** FS-12651 — the line is absent and `net/http` supplies its own UA |
| `empty` | `User-Agent` set to `""` |
| `browser` | a forwarded end user Chrome UA |
| `declaredbot` | same `(+url)` shape, unrelated brand |
| `caller-override` | the fix, then `Source.Headers` overwrites it in the loop |

Every result includes `sentHeaders`, captured with `httptrace.WroteHeaderField`
— what actually went on the wire, not what we intended to send.

## Run locally

```sh
go build -o probe . && ./probe
curl -s localhost:3000/diagnose | jq
curl -s 'localhost:3000/fetch?variant=prefix' | jq
```

## Deploy on Render

Push this directory to a repo, then either commit `render.yaml` and use
**New → Blueprint**, or create a **New → Web Service** manually with:

- **Runtime** Go
- **Build command** `go build -o probe .`
- **Start command** `./probe`
- **Environment variable** `GO_VERSION` = `1.19.13`

Render supplies `PORT`; the server reads it. The free plan is fine — it sleeps
when idle, which does not matter for a probe.

```sh
curl -s https://<your-service>.onrender.com/diagnose | jq '.answer, .results[] | {variant, status}'
```

> **Pin `GO_VERSION`.** `go 1.19` in `go.mod` sets the *language* version, not
> the toolchain — build it with anything newer and `/health` will say so. Since
> the TLS ClientHello changed across Go releases and bot management fingerprints
> it, only a 1.19 build is comparable to staging.

## Reading `answer`

| verdict | meaning | next step |
|---|---|---|
| `UA_IS_SUFFICIENT_HERE` | the deployed UA works from this IP, pre-fix is refused | the header is fine here — verify the running binary really contains it: `strings /taskrouter/taskrouter \| grep 'go-utils v'` |
| `EGRESS_IP_BLOCKED` | every variant refused | no header fixes this; send `akamaiReference` to TUI and ask for an allowlist |
| `UA_NOT_SUFFICIENT_HERE` | deployed UA refused, another variant passes | diff that variant against what go-utils sends |
| `UA_IRRELEVANT_HERE` | everything passes, pre-fix included | this host can't reproduce it; run from taskrouter's egress |

`akamaiReference` is lifted from Akamai's deny page. Give it to TUI — Akamai
support can name the exact rule that fired, which settles UA-vs-IP outright.

Non-200 responses also carry `taskrouterError`, the verbatim message from
`ResolveExternal`, so results line up with the taskrouter log:

```
external URL is unavailable: https://www.tui.se/…/740-425-RIU-TUI-walk-to-beach.jpg (status 403)
```

## Baseline from a developer machine (2026-09-18, go1.25.4)

```
fixed            200   Filestack-Processing-Engine/1.0 (+https://www.filestack.com)
prefix           403   Go-http-client/2.0
empty            403   (no User-Agent on the wire)
browser          403   Mozilla/5.0 … Chrome/140.0.0.0 Safari/537.36
declaredbot      200   SomethingElse/1.0 (+https://example.com)
caller-override  403   Mozilla/5.0 … Chrome/140.0.0.0 Safari/537.36
```

Four things worth knowing:

1. `prefix` sends **`Go-http-client/2.0`**, not `1.1` — the connection negotiates
   HTTP/2 and `net/http` versions its default UA accordingly.
2. `empty` puts **no `User-Agent` on the wire at all**. In Go, `Header.Set(k, "")`
   omits the header rather than sending it blank.
3. `declaredbot` passes, so nothing about Filestack is allowlisted — it is the
   `<Product>/<version> (+<url>)` declared-crawler shape that Akamai accepts.
4. `caller-override` is refused. The `for key, value := range headers` loop runs
   *after* the fix, so a `User-Agent` in `Source.Headers` silently defeats it —
   reachable today through the extended-source form
   `{"url": …, "headers": {…}}`.

## Note

`asset-proxy.js` is the earlier Node probe. It is kept as a cross-check only;
Node speaks HTTP/1.1 and cannot reproduce the Go client. Trust this one.
