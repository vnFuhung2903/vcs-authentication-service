package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	swagger "github.com/swaggo/gin-swagger"
	"github.com/vnFuhung2903/vcs-authentication-service/api"
	_ "github.com/vnFuhung2903/vcs-authentication-service/docs"
	"github.com/vnFuhung2903/vcs-authentication-service/entities"
	"github.com/vnFuhung2903/vcs-authentication-service/infrastructures/databases"
	"github.com/vnFuhung2903/vcs-authentication-service/interfaces"
	"github.com/vnFuhung2903/vcs-authentication-service/pkg/env"
	"github.com/vnFuhung2903/vcs-authentication-service/pkg/logger"
	"github.com/vnFuhung2903/vcs-authentication-service/pkg/middlewares"
	"github.com/vnFuhung2903/vcs-authentication-service/usecases/repositories"
	"github.com/vnFuhung2903/vcs-authentication-service/usecases/services"
	"go.uber.org/zap"
)

// @title VCS SMS API
// @version 1.0
// @description Container Management System API
// @host localhost:8082
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	env, err := env.LoadEnv()
	if err != nil {
		log.Fatalf("Failed to retrieve env: %v", err)
	}

	logger, err := logger.LoadLogger(env.LoggerEnv)
	if err != nil {
		log.Fatalf("Failed to init logger: %v", err)
	}

	postgresDb, err := databases.ConnectPostgresDb(env.PostgresEnv)
	if err != nil {
		log.Fatalf("Failed to create docker client: %v", err)
	}
	postgresDb.AutoMigrate(&entities.User{}, &entities.UserScope{})

	redisRawClient := databases.NewRedisFactory(env.RedisEnv).ConnectRedis()
	defer redisRawClient.Close()
	redisClient := interfaces.NewRedisClient(redisRawClient)

	jwtMiddleware := middlewares.NewJWTMiddleware(env.AuthEnv)
	userRepository := repositories.NewUserRepository(postgresDb)
	authService := services.NewAuthService(userRepository, redisClient, logger, env.AuthEnv)
	authHandler := api.NewAuthHandler(authService, jwtMiddleware)

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"http://auth.localhost", "http://swagger.localhost", "http://frontend.localhost"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
	}))

	authHandler.SetupRoutes(r)
	r.GET("/swagger/*any", swagger.WrapHandler(swaggerFiles.Handler))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	server := &http.Server{
		Addr:    ":8082",
		Handler: r,
	}

	go func() {
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("HTTP server shutdown failed", zap.Error(err))
		}
		logger.Info("Authentication service stopped gracefully")
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to run service: %v", err)
	}
}
