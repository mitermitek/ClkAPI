package main

import (
	"log"

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
