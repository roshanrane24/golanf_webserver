-- -- +goose Up
CREATE TABLE users
(
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP NOT NULL,
    email           TEXT UNIQUE,
    hashed_password TEXT      NOT NULL,
    is_chirpy_red    BOOLEAN          DEFAULT FALSE
);

-- +goose Down
DROP TABLE users;
