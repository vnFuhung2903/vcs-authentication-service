package main

import (
	"log"

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
	redisClient := interfaces.NewRedisClient(redisRawClient)

	jwtMiddleware := middlewares.NewJWTMiddleware(env.AuthEnv)
	userRepository := repositories.NewUserRepository(postgresDb)
	authService := services.NewAuthService(userRepository, redisClient, logger, env.AuthEnv)
	authHandler := api.NewAuthHandler(authService, jwtMiddleware)

	r := gin.Default()
	authHandler.SetupRoutes(r)
	r.GET("/swagger/*any", swagger.WrapHandler(swaggerFiles.Handler))

	if err := r.Run(":8082"); err != nil {
		log.Fatalf("Failed to run service: %v", err)
	} else {
		logger.Info("Authentication service is running on port 8082")
	}
}
