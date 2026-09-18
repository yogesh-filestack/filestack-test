// Command resolve-probe reproduces the exact outbound request taskrouter makes
// when it resolves an external URL — the request that returns 403 in FS-12651.
//
// makeAndDoRequest below is copied from go-utils
// converse/source/resolve.go as deployed (v1.25.1-0.20260917061700-1859b276a5b0).
// Every deviation is marked PROBE: and there are only three.
//
// nginx is not involved anywhere here. This is the first request go-utils makes,
// straight out of the Go process to the origin.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	// The const from resolve.go, verbatim.
	defaultUserAgent = "Filestack-Processing-Engine/1.0 (+https://www.filestack.com)"

	defaultTarget = "https://www.tui.se/cdn/media/sys_master/h07/h51/" +
		"15866047922206/740-425-RIU-TUI-walk-to-beach.jpg"

	chromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

// makeAndDoRequest is go-utils resolve.go:makeAndDoRequest. Keep it that way —
// the value of this program is that it is not a paraphrase.
func makeAndDoRequest(
	ctx context.Context,
	method, addr string,
	headers map[string]string,
	setUserAgent bool, // PROBE 1: false reproduces go-utils before FS-12651.
	wire *[]string, // PROBE 2: captures what actually went on the wire.
) (res *http.Response, err error) {
	h2, cnt := false, 0

	cli := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// PROBE 3: go-utils calls security.IsHostAllowed(req.URL) here. It is
			// an internal allowlist, and the origin answers before any redirect,
			// so it cannot be part of this 403.
			return nil
		},
	}

	traceCtx, cancel := context.WithCancel(ctx)
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(cs tls.ConnectionState, _ error) {
			h2 = cs.NegotiatedProtocol == "h2"
		},
		WroteRequest: func(wri httptrace.WroteRequestInfo) {
			cnt++

			// It's probably going to retry forever, that's why we need to cancel.
			if cnt > 2 && h2 {
				cancel()
			}
		},
		WroteHeaderField: func(key string, values []string) {
			*wire = append(*wire, key+": "+strings.Join(values, ", "))
		},
	}

	var req *http.Request
	req, err = http.NewRequest(method, addr, nil)
	if err != nil {
		return
	}

	if setUserAgent {
		req.Header.Set("User-Agent", defaultUserAgent)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	res, err = cli.Do(req.WithContext(httptrace.WithClientTrace(traceCtx, trace)))
	if err == nil {
		return
	}

	if strings.Contains(err.Error(), context.Canceled.Error()) {
		// Try client without http2 support.
		cli = &http.Client{
			Transport: &http.Transport{
				TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			},
		}
		res, err = cli.Do(req.WithContext(ctx))
		return
	}

	return
}

// variant is one way of filling in the User-Agent, so a single run shows which
// of them the origin accepts from this host.
type variant struct {
	Name    string            `json:"name"`
	What    string            `json:"what"`
	SetUA   bool              `json:"-"`
	Headers map[string]string `json:"headers,omitempty"`
}

var variants = []variant{
	{Name: "fixed", What: "go-utils as deployed today", SetUA: true},
	{Name: "prefix", What: "go-utils before FS-12651 — net/http supplies Go-http-client/1.1", SetUA: false},
	{Name: "empty", What: "User-Agent present but blank", Headers: map[string]string{"User-Agent": ""}},
	{Name: "browser", What: "a forwarded end user Chrome User-Agent", Headers: map[string]string{"User-Agent": chromeUA}},
	{Name: "declaredbot", What: "same (+url) shape, unrelated brand", Headers: map[string]string{"User-Agent": "SomethingElse/1.0 (+https://example.com)"}},
	{Name: "caller-override", What: "the fix, then Source.Headers overwrites it in the loop", SetUA: true, Headers: map[string]string{"User-Agent": chromeUA}},
}

type result struct {
	Variant         string   `json:"variant"`
	What            string   `json:"what"`
	SentHeaders     []string `json:"sentHeaders"`
	Status          int      `json:"status,omitempty"`
	Proto           string   `json:"proto,omitempty"`
	Server          string   `json:"server,omitempty"`
	AkamaiRef       string   `json:"akamaiReference,omitempty"`
	TaskrouterError string   `json:"taskrouterError,omitempty"`
	TransportErr    string   `json:"transportError,omitempty"`
	TookMs          int64    `json:"tookMs"`
}

var refRe = regexp.MustCompile(`Reference\s*#\s*([0-9a-f.]+)`)

// goVersion matters: the TLS ClientHello differs between Go releases, so a
// result is only comparable to staging if this matches what Jenkins built with.
func goVersion() string { return runtime.Version() }

// run performs one attempt and reports it the way ResolveExternal would:
// anything other than 200 becomes the error from the taskrouter log.
func run(ctx context.Context, target string, v variant) result {
	r := result{Variant: v.Name, What: v.What}
	wire := []string{}
	start := time.Now()

	res, err := makeAndDoRequest(ctx, http.MethodGet, target, v.Headers, v.SetUA, &wire)
	r.TookMs = time.Since(start).Milliseconds()
	r.SentHeaders = wire

	if err != nil {
		// ResolveExternal turns this into C500 "failed to resolve external URL".
		r.TransportErr = err.Error()
		return r
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	r.Status = res.StatusCode
	r.Proto = res.Proto
	r.Server = res.Header.Get("Server")

	if m := refRe.FindStringSubmatch(html.UnescapeString(string(body))); m != nil {
		r.AkamaiRef = m[1]
	}

	if res.StatusCode != http.StatusOK {
		// The exact message from resolve.go ResolveExternal.
		r.TaskrouterError = fmt.Sprintf(
			"external URL is unavailable: %s (status %d)", target, res.StatusCode)
	}
	return r
}

func target(req *http.Request) string {
	if u := req.URL.Query().Get("url"); u != "" {
		return u
	}
	if u := os.Getenv("TARGET_URL"); u != "" {
		return u
	}
	return defaultTarget
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{
			"ok": true, "goVersion": goVersion(), "target": defaultTarget,
		})
	})

	// One attempt. ?variant=fixed|prefix|empty|browser|declaredbot|caller-override
	http.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("variant")
		if name == "" {
			name = "fixed"
		}
		for _, v := range variants {
			if v.Name == name {
				writeJSON(w, 200, run(r.Context(), target(r), v))
				return
			}
		}
		writeJSON(w, 400, map[string]string{"error": "unknown variant: " + name})
	})

	// Every variant, sequentially, so the statuses are comparable.
	http.HandleFunc("/diagnose", func(w http.ResponseWriter, r *http.Request) {
		t := target(r)
		out := make([]result, 0, len(variants))
		for _, v := range variants {
			out = append(out, run(r.Context(), t, v))
		}

		fixed, prefix := 0, 0
		anyOK := false
		for _, x := range out {
			if x.Variant == "fixed" {
				fixed = x.Status
			}
			if x.Variant == "prefix" {
				prefix = x.Status
			}
			if x.Status == 200 {
				anyOK = true
			}
		}

		answer := "INCONCLUSIVE"
		switch {
		case fixed == 200 && prefix != 200:
			answer = "UA_IS_SUFFICIENT_HERE — the deployed User-Agent works from this egress " +
				"IP and the pre-fix request is refused. If taskrouter still 403s from comparable " +
				"egress, the running binary is not sending it: " +
				`strings /taskrouter/taskrouter | grep "go-utils v"`
		case fixed == 200 && prefix == 200:
			answer = "UA_IRRELEVANT_HERE — everything passes, including the pre-fix request. " +
				"This host cannot reproduce the failure, so it proves nothing. Run it on the " +
				"same egress as taskrouter."
		case !anyOK:
			answer = "EGRESS_IP_BLOCKED — every variant refused, including ones that pass from " +
				"a developer machine. The block is on this source IP, not the header. No " +
				"User-Agent change fixes this; give the Akamai reference to TUI."
		case fixed != 200:
			answer = "UA_NOT_SUFFICIENT_HERE — the deployed User-Agent is refused here but " +
				"another variant passes. The classifier is weighing more than the header from " +
				"this source."
		}

		writeJSON(w, 200, map[string]interface{}{
			"target":    t,
			"goVersion": goVersion(),
			"answer":    answer,
			"results":   out,
		})
	})

	log.Printf("resolve-probe listening on :%s (target %s)", port, defaultTarget)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
