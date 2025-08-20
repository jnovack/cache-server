// Command http-cache - updated to use pkg/cacheproxy for shared logic.
package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/jnovack/cache-server/pkg/admin"
	"github.com/jnovack/cache-server/pkg/ca"
	"github.com/jnovack/cache-server/pkg/cacheproxy"
	"github.com/jnovack/cache-server/pkg/logging"
	"github.com/jnovack/cache-server/pkg/signals"
)

var (
	flagAddr      = flag.String("addr", ":8081", "HTTP listen address for cache server")
	flagAdminAddr = flag.String("admin-addr", ":8080", "admin HTTP listen address")
	flagCacheDir  = flag.String("cache", "./cache", "cache directory")
	flagLogLevel  = flag.String("log-level", "info", "log level")
	flagRootPem   = flag.String("root-pem", "", "combined root pem (cert+key)")
	flagRootCert  = flag.String("root-cert", "", "root cert file")
	flagRootKey   = flag.String("root-key", "", "root key file")
	flagDN        = flag.String("dn", "", "generate root CA DN")
	flagPrivate   = flag.Bool("private", false, "allow caching responses with Authorization or Cache-Control: private")
)

func main() {
	flag.Parse()
	logging.Setup(*flagLogLevel)
	log.Info().Str("addr", *flagAddr).Msg("starting http-cache")

	if err := os.MkdirAll(*flagCacheDir, 0o755); err != nil {
		log.Fatal().Err(err).Str("dir", *flagCacheDir).Msg("failed to create cache dir")
	}

	// Root CA load or generate (same logic as earlier scaffold)
	var root *ca.RootCA
	var err error
	root, err = ca.NewRootCAFromFiles(*flagRootPem, *flagRootCert, *flagRootKey, *flagCacheDir)
	if err != nil {
		nameSpec := *flagDN
		if nameSpec == "" {
			nameSpec = "jnovack/cache-server"
		}
		name, perr := ca.ParseDN(nameSpec)
		if perr != nil {
			log.Fatal().Err(perr).Msg("failed to parse dn")
		}
		root, err = ca.GenerateRootCASelfSigned(name)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to generate root CA")
		}
		_ = root.SaveCombined(filepath.Join(*flagCacheDir, "root.pem"))
		root.CacheDir = *flagCacheDir
	} else {
		root.CacheDir = *flagCacheDir
	}

	metrics := admin.NewMetrics()

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/healthz", admin.HandleHealth)
	adminMux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) { admin.HandleMetrics(w, metrics) })
	adminMux.HandleFunc("/statusz", func(w http.ResponseWriter, r *http.Request) { admin.HandleStatusz(w, metrics) })
	adminMux.HandleFunc("/varz", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]interface{}{
			"addr":  *flagAddr,
			"cache": *flagCacheDir,
		}
		admin.HandleVarz(w, cfg)
	})
	adminMux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		if len(root.PEM()) == 0 {
			http.Error(w, "no cert available", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(root.PEM())
	})

	adminSrv := &http.Server{Addr: *flagAdminAddr, Handler: adminMux}
	go func() {
		log.Info().Str("addr", *flagAdminAddr).Msg("admin HTTP starting")
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("admin HTTP failed")
		}
	}()

	// cache server using shared handler
	cfg := cacheproxy.Config{
		CacheDir: *flagCacheDir,
		Private:  *flagPrivate,
		Metrics:  metrics,
		RootCA:   root,
	}
	mainMux := http.NewServeMux()
	mainMux.HandleFunc("/", cacheproxy.CacheHandler(cfg))
	srv := &http.Server{Addr: *flagAddr, Handler: mainMux}

	lnErrCh := make(chan error, 1)
	go func() { lnErrCh <- srv.ListenAndServe() }()

	// signal handling
	stopCh := make(chan struct{})
	ctx := signals.Setup(stopCh)

	select {
	case <-ctx.Done():
		log.Info().Msg("shutdown requested")
	case err := <-lnErrCh:
		if err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("http server failed")
		}
	}

	ctxShut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctxShut)
	_ = adminSrv.Shutdown(ctxShut)
	log.Info().Msg("http-cache stopped")
}
