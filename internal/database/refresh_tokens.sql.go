// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: refresh_tokens.sql

package database

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const addRefreshToken = `-- name: AddRefreshToken :execrows
INSERT INTO refresh_tokens(token, created_at, updated_at, user_id, expires_at)
VALUES ($1,
        NOW(),
        NOW(),
        $2,
        $3) RETURNING token, created_at, updated_at, user_id, expires_at, revoked_at
`

type AddRefreshTokenParams struct {
	Token     string
	UserID    uuid.UUID
	ExpiresAt time.Time
}

func (q *Queries) AddRefreshToken(ctx context.Context, arg AddRefreshTokenParams) (int64, error) {
	result, err := q.db.ExecContext(ctx, addRefreshToken, arg.Token, arg.UserID, arg.ExpiresAt)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

const getRefreshToken = `-- name: GetRefreshToken :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at
FROM refresh_tokens
WHERE token = $1
`

func (q *Queries) GetRefreshToken(ctx context.Context, token string) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getRefreshToken, token)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const rovokeToken = `-- name: RovokeToken :execrows
UPDATE refresh_tokens
SET updated_at = NOW(),
    revoked_at = NOW()
WHERE token = $1
`

func (q *Queries) RovokeToken(ctx context.Context, token string) (int64, error) {
	result, err := q.db.ExecContext(ctx, rovokeToken, token)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
