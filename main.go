package main

import (
	"crypto/rand"
	"database/sql"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       uuid.UUID
	Username string
	Password string
}

type Url struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	HashURL     string
	OriginalURL string
}

type Claims struct {
	jwt.RegisteredClaims
}

type UserRegistrationDTO struct {
	Username string `json:"username" binding:"required,min=3,max=20"`
	Password string `json:"password" binding:"required"`
}

type UserRegisteredDTO struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
}

type UserLoginDTO struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UserLoggedInDTO struct {
	Token string `json:"token"`
}

type ShortUrlCreation struct {
	OriginalURL string `json:"original_url" binding:"required,min=10,max=2048"`
}

type ShortUrlCreated struct {
	ShortURL string `json:"short_url"`
}

var db *sql.DB
var jwtKey []byte

const (
	charset    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	hashLength = 8
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Failed to load .env file: %v", err)
	}

	jwtKey = []byte(os.Getenv("JWT_KEY"))
	if string(jwtKey) == "" {
		log.Fatal("JWT_KEY is not set")
	}

	dbURL := os.Getenv("DB_URL")
	if string(dbURL) == "" {
		log.Fatal("DB_URL is not set")
	}

	db, err = sql.Open("mysql", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping the database: %v", err)
	}

	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	log.Println("Database connection initialized successfully")

	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	r.POST("/signup", signup)
	r.POST("/signin", signin)

	r.POST("/urls", authMiddleware(), createShortURL)

	r.Run()
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

	resp := UserRegisteredDTO{
		ID:       user.ID,
		Username: user.Username,
	}

	c.JSON(http.StatusCreated, resp)
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

	resp := UserLoggedInDTO{
		Token: token,
	}

	c.JSON(http.StatusOK, resp)
}

func createShortURL(c *gin.Context) {
	var req ShortUrlCreation
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

	scheme := "http"
	if c.Request.URL.Scheme != "" {
		scheme = c.Request.URL.Scheme
	}

	shortURL := scheme + "://" + c.Request.Host + "/" + url.HashURL

	resp := ShortUrlCreated{
		ShortURL: shortURL,
	}

	c.JSON(http.StatusCreated, resp)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateJWT(userID uuid.UUID) (string, error) {
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func getUserIDFromToken(c *gin.Context) (uuid.UUID, error) {
	tokenString := c.GetHeader("Authorization")
	claims := &Claims{}

	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, err
	}

	return userID, nil
}

func isUsernameTaken(username string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(id) FROM users WHERE username = ?", username).Scan(&count)
	return err == nil && count > 0
}

func insertUser(user User) error {
	_, err := db.Exec("INSERT INTO users (id, username, password) VALUES (?, ?, ?)", user.ID.String(), user.Username, user.Password)
	return err
}

func getUserByUsername(username string) (User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password)
	return user, err
}

func insertUrl(url Url) error {
	_, err := db.Exec("INSERT INTO urls (id, user_id, hash_url, original_url) VALUES (?, ?, ?, ?)", url.ID.String(), url.UserID, url.HashURL, url.OriginalURL)
	return err
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

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		c.Next()
	}
}
