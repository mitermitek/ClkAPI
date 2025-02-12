CREATE TABLE urls (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    hash_url VARCHAR(8) NOT NULL UNIQUE,
    original_url TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
