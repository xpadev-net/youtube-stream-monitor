package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/xpadev-net/youtube-stream-tracker/internal/config"
	"github.com/xpadev-net/youtube-stream-tracker/internal/log"
	"github.com/xpadev-net/youtube-stream-tracker/internal/worker"
)

func main() {
	// Initialize logger
	if err := log.InitJSON(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	log.Info("starting Worker")

	// Load configuration
	cfg, err := config.LoadWorkerConfig()
	if err != nil {
		log.Fatal("failed to load configuration", zap.Error(err))
	}

	log.Info("configuration loaded",
		zap.String("monitor_id", cfg.MonitorID),
		zap.String("stream_url", cfg.StreamURL),
		zap.String("callback_url", cfg.CallbackURL),
	)

	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	// Create router for health checks
	router := gin.New()
	router.Use(gin.Recovery())

	// Health check endpoints
	router.GET("/healthz", healthzHandler)
	router.GET("/readyz", readyzHandler)

	// Create HTTP server for health checks (port 8081)
	srv := &http.Server{
		Addr:    ":8081",
		Handler: router,
	}

	// Start health check server in a goroutine
	go func() {
		log.Info("starting health check server", zap.Int("port", 8081))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("health check server error", zap.Error(err))
		}
	}()

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info("received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	}()

	// Create and run the worker
	w := worker.NewWorker(cfg)
	if len(cfg.Metadata) > 0 {
		w.SetMetadata(cfg.Metadata)
	}
	if err := w.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("worker error", zap.Error(err))
	}

	// Shutdown health check server with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("error shutting down health server", zap.Error(err))
	}

	log.Info("worker stopped")
}

func healthzHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func readyzHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
