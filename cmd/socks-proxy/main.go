package main

import (
	"context"
	"net/http"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/jnovack/cache-server/pkg/admin"
	"github.com/jnovack/cache-server/pkg/ca"
	"github.com/jnovack/cache-server/pkg/cacheproxy"
	"github.com/jnovack/cache-server/pkg/logging"
	"github.com/jnovack/cache-server/pkg/signals"
	"github.com/jnovack/cache-server/pkg/socks"
	"github.com/jnovack/flag"
)

var (
	flagSocksAddr = flag.String("socks-addr", ":1080", "SOCKS5 listen address")
	flagAdminAddr = flag.String("admin-addr", ":8080", "admin HTTP listen address")
	flagCacheDir  = flag.String("cache", "./cache", "cache directory")
	flagLogLevel  = flag.String("log-level", "info", "log level")
	flagRootPem   = flag.String("root-pem", *flagCacheDir+"/root.pem", "combined root pem (cert+key)")
	flagRootCert  = flag.String("root-cert", "", "root cert file")
	flagRootKey   = flag.String("root-key", "", "root key file")
	flagDN        = flag.String("dn", "", "generate root CA DN")
	flagPrivate   = flag.Bool("private", false, "allow caching responses with Authorization or Cache-Control: private")
)

func main() {
	flag.Parse()
	logging.Setup(*flagLogLevel)

	metrics := admin.NewMetrics()

	// Root CA: load or generate (fallback CN as requested earlier).
	root, err := ca.NewRootCAFromFiles(*flagRootPem, *flagRootCert, *flagRootKey, *flagCacheDir)
	if err != nil {
		nameSpec := *flagDN
		if nameSpec == "" {
			nameSpec = "jnovack/cache-server"
		}
		name, perr := ca.ParseDN(nameSpec)
		if perr != nil {
			log.Fatal().Err(perr).Msg("failed to parse DN")
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

	cfg := cacheproxy.Config{
		CacheDir: *flagCacheDir,
		Private:  *flagPrivate,
		Metrics:  metrics,
		RootCA:   root,
	}

	// Admin endpoints
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/healthz", admin.HandleHealth)
	adminMux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) { admin.HandleMetrics(w, metrics) })
	adminMux.HandleFunc("/statusz", func(w http.ResponseWriter, r *http.Request) { admin.HandleStatusz(w, metrics) })
	adminMux.HandleFunc("/varz", func(w http.ResponseWriter, r *http.Request) {
		admin.HandleVarz(w, map[string]any{
			"socks-addr": *flagSocksAddr,
			"cache":      *flagCacheDir,
			"private":    *flagPrivate,
		})
	})
	adminMux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		if len(root.PEM()) == 0 {
			http.Error(w, "no cert available", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")

		// Set the Content-Disposition header to suggest the filename
		w.Header().Set("Content-Disposition", "attachment; filename=\"root.pem\"")

		_, _ = w.Write(root.PEM())
	})
	adminSrv := &http.Server{Addr: *flagAdminAddr, Handler: adminMux}
	go func() {
		log.Info().Str("addr", *flagAdminAddr).Msg("admin HTTP starting")
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("admin HTTP failed")
		}
	}()

	s := &socks.Server{
		Addr:     *flagSocksAddr,
		CacheCfg: cfg,
		Metrics:  metrics,
		RootCA:   root,
	}
	if err := s.Start(); err != nil {
		log.Fatal().Err(err).Msg("failed to start socks server")
	}

	stopCh := make(chan struct{})
	ctx := signals.Setup(stopCh)

	<-ctx.Done()
	log.Info().Msg("shutdown requested")

	shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = adminSrv.Shutdown(shCtx)
	_ = s.Close()
	log.Info().Msg("socks-cache stopped")
}
