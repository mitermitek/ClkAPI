package main

import (
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

type User struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username" binding:"required,min=3,max=20"`
	Password string    `json:"password" binding:"required"`
}

type Claims struct {
	jwt.RegisteredClaims
}

type SignUpRequestDTO struct {
	Username string `json:"username" binding:"required,min=3,max=20"`
	Password string `json:"password" binding:"required"`
}

type SignUpResponseDTO struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
}

type SignInRequestDTO struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type SignInResponseDTO struct {
	Token string `json:"token"`
}

var db *sql.DB
var jwtKey []byte

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

	r.Run()
}

func signup(c *gin.Context) {
	var req SignUpRequestDTO
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

	resp := SignUpResponseDTO{
		ID:       user.ID,
		Username: user.Username,
	}

	c.JSON(http.StatusCreated, resp)
}

func signin(c *gin.Context) {
	var req SignInRequestDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := getUserByUsername(req.Username)
	if err != nil || !verifyPassword(req.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	token, err := generateJWT()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	resp := SignInResponseDTO{
		Token: token,
	}

	c.JSON(http.StatusOK, resp)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateJWT() (string, error) {
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
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
