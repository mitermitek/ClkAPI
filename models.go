package main

import "github.com/google/uuid"

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
