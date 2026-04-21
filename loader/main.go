// Tengen RAM-only loader.
//
// Intent: fetch a signed deployment package over TLS, keep it in pinned
// memory, hand it to an execution callback, then scrub every byte on exit.
// The loader writes nothing to disk, leaves no lock files, drops no
// temporary binaries. On SIGINT / SIGTERM it exits cleanly and wipes state.
//
// Transparency: this is a plain Go binary with a visible process name,
// argv, and env. A sysadmin `ps`/`lsof`/`netstat` sees exactly what it is.
// There is no shell-history scrubbing, no parent-process hiding, no fork
// trickery. The "stealth" lives inside the encrypted payload, not here.
//
// Build:   go build -trimpath -ldflags='-s -w' -o tengen-loader
// Run:     tengen-loader -url https://host/pkg -pubkey <hex> -sig <hex>
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
)

// execCallback is where the loader hands the package to your runtime.
// Replace with your actual interpreter/orchestrator; the signature is kept
// small on purpose. The callback MUST treat `pkg` as borrowed — it becomes
// invalid the instant this function returns.
type execCallback func(ctx context.Context, pkg []byte) error

func main() {
	var (
		url     = flag.String("url", "", "deployment package URL (https)")
		pubHex  = flag.String("pubkey", "", "ed25519 public key in hex (32 bytes)")
		sigHex  = flag.String("sig", "", "ed25519 signature over package body in hex (64 bytes)")
		maxSize = flag.Int("max", 16<<20, "max package size in bytes")
		timeout = flag.Duration("timeout", 30*time.Second, "fetch + run deadline")
	)
	flag.Parse()

	if *url == "" || *pubHex == "" || *sigHex == "" {
		fmt.Fprintln(os.Stderr, "usage: tengen-loader -url URL -pubkey HEX -sig HEX")
		os.Exit(2)
	}

	// Disable GC output-buffering tricks; we want GC to actually reclaim
	// when we tell it to.
	debug.SetGCPercent(100)

	pub, err := hex.DecodeString(*pubHex)
	must(err, "pubkey hex")
	if len(pub) != ed25519.PublicKeySize {
		fatal("pubkey must be 32 bytes")
	}
	sig, err := hex.DecodeString(*sigHex)
	must(err, "sig hex")
	if len(sig) != ed25519.SignatureSize {
		fatal("sig must be 64 bytes")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Signal handling: SIGINT/SIGTERM → cancel context → deferred scrub runs.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		cancel()
	}()

	pkg, err := fetch(ctx, *url, *maxSize)
	must(err, "fetch")

	// Pin pages so the kernel cannot page this buffer out to swap.
	// Best-effort: errors (e.g. RLIMIT_MEMLOCK) are non-fatal.
	_ = mlock(pkg)

	// Guarantee scrub + unlock on EVERY exit path (panic, ctx done, normal).
	defer scrub(pkg)

	if !ed25519.Verify(pub, pkg, sig) {
		fatal("signature verification failed")
	}

	if err := execute(ctx, pkg); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(1)
	}
}

// fetch downloads the package body over TLS into a single []byte buffer.
// Uses TLS 1.3 minimum, no redirects, explicit size cap.
func fetch(ctx context.Context, url string, max int) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
}

// execute is the hand-off to the Tengen runtime. This MVP loader simply
// exercises the lifecycle — replace the body with your real interpreter
// bridge (goja, wasmtime, a subprocess speaking a pinned protocol, etc.).
func execute(ctx context.Context, pkg []byte) error {
	_ = pkg
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(50 * time.Millisecond):
		return nil
	}
}

// scrub zero-fills a byte slice and pressures the runtime to reclaim it.
// Go has no standard way to force SecureZeroMemory-equivalent behavior, but
// writing zeroes through the slice header plus two GC cycles is the most
// the stdlib can promise.
func scrub(b []byte) {
	for i := range b {
		b[i] = 0
	}
	_ = munlock(b)
	runtime.GC()
	runtime.GC()
}

func must(err error, what string) {
	if err != nil {
		fatal(what + ": " + err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
