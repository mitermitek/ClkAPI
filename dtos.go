package main

type UserRegistrationDTO struct {
	Username string `json:"username" binding:"required,min=3,max=20"`
	Password string `json:"password" binding:"required"`
}

type UserRegisteredDTO struct {
	Username string `json:"username"`
}

type UserLoginDTO struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UserLoggedInDTO struct {
	Token string `json:"token"`
}

type ShortUrlCreationDTO struct {
	OriginalURL string `json:"original_url" binding:"required,min=10,max=2048"`
}

type ShortUrlCreatedDTO struct {
	ShortURL string `json:"short_url"`
}
