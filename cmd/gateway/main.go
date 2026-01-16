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

	"github.com/xpadev-net/youtube-stream-tracker/internal/api"
	"github.com/xpadev-net/youtube-stream-tracker/internal/config"
	"github.com/xpadev-net/youtube-stream-tracker/internal/db"
	"github.com/xpadev-net/youtube-stream-tracker/internal/httpapi"
	"github.com/xpadev-net/youtube-stream-tracker/internal/k8s"
	"github.com/xpadev-net/youtube-stream-tracker/internal/log"
	"github.com/xpadev-net/youtube-stream-tracker/internal/webhook"
)

func main() {
	// Initialize logger
	if err := log.InitJSON(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	log.Info("starting API Gateway")

	// Load configuration
	cfg, err := config.LoadGatewayConfig()
	if err != nil {
		log.Fatal("failed to load configuration", zap.Error(err))
	}

	log.Info("configuration loaded",
		zap.String("environment", cfg.Environment),
		zap.Int("port", cfg.Port),
		zap.String("namespace", cfg.Namespace),
	)

	// Connect to database
	ctx := context.Background()
	database, err := db.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal("failed to connect to database", zap.Error(err))
	}
	defer database.Close()

	// Run migrations
	if err := database.Migrate(ctx); err != nil {
		log.Fatal("failed to run migrations", zap.Error(err))
	}

	// Create repository
	repo := db.NewMonitorRepository(database)

	// Create K8s client and reconciler
	k8sClient, err := k8s.NewClient(k8s.Config{
		InCluster:      cfg.InCluster,
		KubeConfigPath: cfg.KubeConfigPath,
		Namespace:      cfg.Namespace,
		WorkerImage:    cfg.WorkerImage,
		WorkerImageTag: cfg.WorkerImageTag,
	})
	if err != nil {
		log.Fatal("failed to create k8s client", zap.Error(err))
	}
	webhookSender := webhook.NewSender(cfg.WebhookSigningKey)
	reconciler := k8s.NewReconciler(k8sClient, repo, webhookSender, cfg.ReconcileTimeout)

	// Create API handler
	handler := api.NewHandler(repo, cfg.MaxMonitors, reconciler, cfg.InternalAPIKey, cfg.WebhookSigningKey)

	// Set Gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestLogger())

	// Health check endpoints (no auth required)
	router.GET("/healthz", healthzHandler(database))
	router.GET("/readyz", readyzHandler(database))

	// External API v1 (API key auth required)
	v1 := router.Group("/api/v1")
	v1.Use(httpapi.APIKeyAuth(cfg.APIKey))
	{
		v1.POST("/monitors", handler.CreateMonitor)
		v1.GET("/monitors", handler.ListMonitors)
		v1.GET("/monitors/:monitor_id", handler.GetMonitor)
		v1.DELETE("/monitors/:monitor_id", handler.DeleteMonitor)
	}

	// Internal API (internal API key auth required)
	internal := router.Group("/internal/v1")
	internal.Use(httpapi.InternalAPIKeyAuth(cfg.InternalAPIKey))
	{
		internal.PUT("/monitors/:monitor_id/status", handler.UpdateMonitorStatus)
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Info("starting HTTP server", zap.Int("port", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("failed to start server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("server forced to shutdown", zap.Error(err))
	}

	log.Info("server stopped")
}

func healthzHandler(database *db.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func readyzHandler(database *db.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := database.Health(c.Request.Context()); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready", "error": "database connection failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		log.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}
