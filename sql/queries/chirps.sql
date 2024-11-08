-- name: AddChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (gen_random_uuid(),
        NOW(),
        NOW(),
        $1,
        $2)
RETURNING *;

-- name: GetChirps :many
SELECT *
FROM chirps
ORDER BY created_at
;

-- name: GetChirpsDesc :many
SELECT *
FROM chirps
ORDER BY created_at DESC
;

-- name: GetChirpsForUser :many
SELECT *
FROM chirps
WHERE user_id = $1
ORDER BY created_at
;

-- name: GetChirpsForUserDesc :many
SELECT *
FROM chirps
WHERE user_id = $1
ORDER BY created_at DESC
;

-- name: GetChirp :one
SELECT *
FROM chirps
WHERE id = $1
ORDER BY created_at
;

-- name: DeleteChirp :exec
DELETE
FROM
    chirps
WHERE
    id = $1
RETURNING *
;