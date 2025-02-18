package main

import (
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	if err := initializeApp(); err != nil {
		log.Fatalf("Failed to initialize app: %v", err)
	}

	router := setupRouter()
	router.Run()
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Routes statiques
	r.GET("/robots.txt", serveRobotsTxt)
	r.GET("/", handleHome)
	r.GET("/ping", handlePing)

	// Routes d'authentification
	r.POST("/signup", signup)
	r.POST("/signin", signin)

	// Routes protégées
	r.POST("/urls", authMiddleware(), createShortURL)

	// Route de redirection
	r.GET("/:hashURL", redirectToOriginalURL)

	return r
}
