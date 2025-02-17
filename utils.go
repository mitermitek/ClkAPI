package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

const (
	charset    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	hashLength = 8
)

func initializeApp() error {
	if err := godotenv.Load(); err != nil {
		return err
	}

	env := os.Getenv("ENV")
	if env == "" {
		return fmt.Errorf("ENV is not set")
	}

	jwtKey = []byte(os.Getenv("JWT_KEY"))
	if string(jwtKey) == "" {
		return fmt.Errorf("JWT_KEY is not set")
	}

	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		return fmt.Errorf("DB_URL is not set")
	}

	if err := initializeDatabase(dbURL); err != nil {
		return err
	}

	if env == "prod" {
		gin.SetMode(gin.ReleaseMode)
	}

	return nil
}

func generateRandomString(length int) (string, error) {
	result := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		index, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", err
		}
		result[i] = charset[index.Int64()]
	}

	return string(result), nil
}

func getShortURL(c *gin.Context, hashURL string) string {
	scheme := "http"
	if c.Request.URL.Scheme != "" {
		scheme = c.Request.URL.Scheme
	}
	return scheme + "://" + c.Request.Host + "/" + hashURL
}
