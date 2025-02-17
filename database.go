package main

import (
	"database/sql"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func initializeDatabase(dbURL string) error {
	var err error
	db, err = sql.Open("mysql", dbURL)
	if err != nil {
		return err
	}

	if err := db.Ping(); err != nil {
		return err
	}

	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	return nil
}

func isUsernameTaken(username string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(id) FROM users WHERE username = ?", username).Scan(&count)
	return err == nil && count > 0
}

func insertUser(user User) error {
	_, err := db.Exec("INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
		user.ID.String(), user.Username, user.Password)
	return err
}

func getUserByUsername(username string) (User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.Password)
	return user, err
}

func insertUrl(url Url) error {
	_, err := db.Exec("INSERT INTO urls (id, user_id, hash_url, original_url) VALUES (?, ?, ?, ?)",
		url.ID.String(), url.UserID, url.HashURL, url.OriginalURL)
	return err
}

func getOriginalURLByHash(hashURL string) (string, error) {
	var originalURL string
	err := db.QueryRow("SELECT original_url FROM urls WHERE hash_url = ?", hashURL).
		Scan(&originalURL)
	return originalURL, err
}
