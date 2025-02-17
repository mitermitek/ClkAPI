package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func serveRobotsTxt(c *gin.Context) {
	c.File("robots.txt")
}

func handleHome(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "hello"})
}

func handlePing(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "pong"})
}

func signup(c *gin.Context) {
	var req UserRegistrationDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if isUsernameTaken(req.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already taken"})
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	userID, err := uuid.NewV7()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate UUID"})
		return
	}

	user := User{
		ID:       userID,
		Username: req.Username,
		Password: hashedPassword,
	}

	if err := insertUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert user into database"})
		return
	}

	c.JSON(http.StatusCreated, UserRegisteredDTO{Username: user.Username})
}

func signin(c *gin.Context) {
	var req UserLoginDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := getUserByUsername(req.Username)
	if err != nil || !verifyPassword(req.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	token, err := generateJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, UserLoggedInDTO{Token: token})
}

func createShortURL(c *gin.Context) {
	var req ShortUrlCreationDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := getUserIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	urlID, err := uuid.NewV7()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate UUID"})
		return
	}

	urlHash, err := generateRandomString(hashLength)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate short URL hash"})
		return
	}

	url := Url{
		ID:          urlID,
		UserID:      userID,
		HashURL:     urlHash,
		OriginalURL: req.OriginalURL,
	}

	if err := insertUrl(url); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert url into database"})
		return
	}

	shortURL := getShortURL(c, url.HashURL)
	c.JSON(http.StatusCreated, ShortUrlCreatedDTO{ShortURL: shortURL})
}

func redirectToOriginalURL(c *gin.Context) {
	hashURL := c.Param("hashURL")

	originalURL, err := getOriginalURLByHash(hashURL)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
		return
	}

	c.Redirect(http.StatusFound, originalURL)
}
