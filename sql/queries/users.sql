-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (gen_random_uuid(),
        NOW(),
        NOW(),
        $1,
        $2)
RETURNING *;

-- name: DeleteAllUsers :execrows

DELETE
FROM users;

-- name: GetUserDetailsByEmail :one

SELECT *
FROM users
WHERE users.email = $1
;
-- name: GetUserDetailsById :one

SELECT *
FROM users
WHERE users.id = $1
;

-- name: UpdateUserEmailAndPassword :one
UPDATE users
SET email    = $1,
    hashed_password = $2,
    updated_at = NOW()
WHERE id = $3
RETURNING *
;

-- name: UpgradeToRed :execrows
UPDATE users
SET is_chirpy_red = TRUE
WHERE id = $1
;