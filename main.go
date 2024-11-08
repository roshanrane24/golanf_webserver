package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/roshanrane24/go-web-server/internal/auth"
	db "github.com/roshanrane24/go-web-server/internal/database"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	time "time"
)

type apiConfig struct {
	queries        *db.Queries
	jwtSecret      string
	polkaKey       string
	fileserverHits atomic.Int32
}

func (config *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Add("Cache-Control", "no-cache")
		config.fileserverHits.Add(1)
		next.ServeHTTP(writer, request)
	})
}

func (config *apiConfig) reset() {
	config.fileserverHits.Store(0)
}

var (
	logger = log.New(os.Stdout, "logger: ", log.Lshortfile)
)

func main() {
	// Load ENV Vars
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Failed to load environment variables")
	}
	DBURL := os.Getenv("DB_URL")
	PLATFORM := os.Getenv("PLATFORM")
	POLKA_KEY := os.Getenv("POLKA_KEY")

	// Setup DB
	dbConn, err := sql.Open("postgres", DBURL)
	if err != nil {
		return
	}

	// Setup Server
	config := apiConfig{
		queries:   db.New(dbConn),
		jwtSecret: os.Getenv("JWT_SECRET"),
		polkaKey:  POLKA_KEY,
	}
	mux := http.NewServeMux()

	server := http.Server{
		Addr:     ":8080",
		Handler:  mux,
		ErrorLog: logger,
	}

	// Handler Mapping
	mux.Handle(
		"/app/",
		http.StripPrefix(
			"/app",
			config.middlewareMetricsInc(
				http.FileServer(http.Dir("./")),
			),
		),
	)
	mux.Handle(
		"/app/assets/",
		http.StripPrefix(
			"/app",
			config.middlewareMetricsInc(
				http.FileServer(http.Dir("./")),
			),
		),
	)
	mux.HandleFunc(
		"GET /api/healthz",
		func(respWriter http.ResponseWriter, req *http.Request) {
			respWriter.Header().Add("Content-Type", "text/plain; charset=utf-8")
			respWriter.WriteHeader(200)
			_, err := respWriter.Write(bytes.NewBufferString("OK").Bytes())
			if err != nil {
				respWriter.WriteHeader(501)
			}
		},
	)

	mux.HandleFunc(
		"GET /admin/metrics",
		func(respWriter http.ResponseWriter, req *http.Request) {
			respWriter.Header().Add("Content-Type", "text/html; charset=utf-8")
			respWriter.WriteHeader(200)
			_, err := respWriter.Write(bytes.NewBufferString(
				fmt.Sprintf("<html>\n  <body>\n    <h1>Welcome, Chirpy Admin</h1>\n    <p>Chirpy has been visited %d times!</p>\n  </body>\n</html>",
					int(config.fileserverHits.Load()))).Bytes())
			if err != nil {
				respWriter.WriteHeader(501)
			}
		},
	)

	mux.HandleFunc(
		"POST /admin/reset",
		func(respWriter http.ResponseWriter, req *http.Request) {
			respWriter.Header().Add("Content-Type", "text/plain; charset=utf-8")

			// reset Visits
			config.reset()

			// Remove all users
			if PLATFORM == "dev" {
				respWriter.WriteHeader(200)
				_, err := config.queries.DeleteAllUsers(req.Context())
				if err != nil {
					return
				}
			} else {
				respWriter.WriteHeader(403)
			}
		},
	)

	mux.HandleFunc(
		"POST /api/users",
		func(respWriter http.ResponseWriter, req *http.Request) {
			body := struct {
				Password string `json:"password"`
				Email    string `json:"email"`
			}{}

			respWriter.Header().Add("Content-Type", "text/json")

			// JSON
			var buffer bytes.Buffer
			decoder := json.NewDecoder(req.Body)
			encoder := json.NewEncoder(&buffer)
			err := decoder.Decode(&body)
			if err != nil {
				respWriter.WriteHeader(400)
				err := encoder.Encode(struct {
					Error string `json:"error"`
				}{"Something went wrong"})
				if err != nil {
					return
				}

				_, err = respWriter.Write(buffer.Bytes())
				if err != nil {
					return
				}
			}

			//get hashed password
			body.Password, err = auth.HashPassword(body.Password)
			if err != nil {
				respWriter.WriteHeader(400)
				err := encoder.Encode(struct {
					Error string `json:"error"`
				}{"Something went wrong"})
				if err != nil {
					return
				}

				_, err = respWriter.Write(buffer.Bytes())
				if err != nil {
					return
				}
			}

			// save user to DB
			user, err := config.queries.CreateUser(req.Context(), db.CreateUserParams{
				Email: sql.NullString{
					String: body.Email,
					Valid:  true,
				},
				HashedPassword: body.Password},
			)
			if err != nil {
				respWriter.WriteHeader(400)
				err := encoder.Encode(struct {
					Error string `json:"error"`
				}{"Something went wrong" + err.Error()})
				if err != nil {
					return
				}

				_, err = respWriter.Write(buffer.Bytes())
				if err != nil {
					return
				}
			} else {
				respWriter.WriteHeader(201)

				err := encoder.Encode(struct {
					ID          uuid.UUID `json:"id"`
					CreatedAt   time.Time `json:"created_at"`
					UpdatedAt   time.Time `json:"updated_at"`
					Email       string    `json:"email"`
					IsChirpyRed bool      `json:"is_chirpy_red"`
				}{
					ID:          user.ID,
					CreatedAt:   user.CreatedAt,
					UpdatedAt:   user.UpdatedAt,
					Email:       user.Email.String,
					IsChirpyRed: user.IsChirpyRed.Valid && user.IsChirpyRed.Bool,
				})
				if err != nil {
					return
				}

				_, err = respWriter.Write(buffer.Bytes())
				if err != nil {
					return
				}

			}
		},
	)

	mux.HandleFunc(
		"PUT /api/users",
		func(writer http.ResponseWriter, request *http.Request) {
			var buffer bytes.Buffer
			encoder := json.NewEncoder(&buffer)
			decoder := json.NewDecoder(request.Body)

			type userRequest struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}

			userDetails := userRequest{}
			err := decoder.Decode(&userDetails)
			if err != nil {
				writer.WriteHeader(401)
				return
			}

			jwt, err := auth.GetBearerToken(request.Header)
			if err != nil {
				writer.WriteHeader(401)
				return
			}

			userId, err := auth.ValidateJWT(jwt, config.jwtSecret)
			if err != nil {
				writer.WriteHeader(401)
				return
			}

			userDetails.Password, err = auth.HashPassword(userDetails.Password)
			if err != nil {
				writer.WriteHeader(500)
				writer.Write([]byte(err.Error()))
				return
			}

			user, err := config.queries.UpdateUserEmailAndPassword(
				request.Context(),
				db.UpdateUserEmailAndPasswordParams{
					Email:          sql.NullString{userDetails.Email, true},
					HashedPassword: userDetails.Password,
					ID:             userId,
				},
			)
			if err != nil {
				writer.WriteHeader(500)
				writer.Write([]byte(err.Error()))
				return
			}

			writer.WriteHeader(200)

			err = encoder.Encode(struct {
				ID          uuid.UUID `json:"id"`
				CreatedAt   time.Time `json:"created_at"`
				UpdatedAt   time.Time `json:"updated_at"`
				Email       string    `json:"email"`
				IsChirpyRed bool      `json:"is_chirpy_red"`
			}{
				ID:          user.ID,
				CreatedAt:   user.CreatedAt,
				UpdatedAt:   user.UpdatedAt,
				Email:       user.Email.String,
				IsChirpyRed: user.IsChirpyRed.Valid && user.IsChirpyRed.Bool,
			})
			if err != nil {
				writer.WriteHeader(500)
				writer.Write([]byte(err.Error()))
				return
			}

			_, err = writer.Write(buffer.Bytes())
			if err != nil {
				return
			}

		},
	)

	mux.HandleFunc(
		"POST /api/chirps",
		func(writer http.ResponseWriter, request *http.Request) {
			token, err := auth.GetBearerToken(request.Header)
			if err != nil {
				writer.WriteHeader(401)
				writer.Write([]byte(err.Error()))
				return
			}
			userId, err := auth.ValidateJWT(token, config.jwtSecret)
			if err != nil {
				writer.WriteHeader(401)
				writer.Write([]byte(err.Error()))
				return
			}
			id, err := config.queries.GetUserDetailsById(request.Context(), userId)
			if err != nil {
				writer.WriteHeader(501)
				writer.Write([]byte(err.Error()))
				return
			}

			if id.ID != userId {
				writer.WriteHeader(401)
				writer.Write([]byte(err.Error()))
				return
			}

			body := struct {
				Body string `json:"body"`
			}{}

			writer.Header().Add("Content-Type", "text/json")

			// JSON
			var buffer bytes.Buffer
			decoder := json.NewDecoder(request.Body)
			encoder := json.NewEncoder(&buffer)
			err = decoder.Decode(&body)
			if err != nil {
				writer.WriteHeader(400)
				_ = encoder.Encode(struct {
					Error string `json:"error"`
				}{"Something went wrong" + err.Error()})
				_, _ = writer.Write(buffer.Bytes())
			}

			// add chirp to db
			body.Body, err = validateChirp(body.Body)
			if err != nil {
				writer.WriteHeader(400)
				_ = encoder.Encode(struct {
					Error string `json:"error"`
				}{"Something went wrong" + err.Error()})
				_, _ = writer.Write(buffer.Bytes())
				return
			}
			chirp, err := config.queries.AddChirp(request.Context(), db.AddChirpParams{
				Body:   body.Body,
				UserID: userId,
			})
			if err != nil {
				writer.WriteHeader(400)
			} else {
				writer.WriteHeader(201)

				err := encoder.Encode(struct {
					ID        uuid.UUID `json:"id"`
					CreatedAt time.Time `json:"created_at"`
					UpdatedAt time.Time `json:"updated_at"`
					Body      string    `json:"body"`
					UserID    uuid.UUID `json:"user_id"`
				}{
					chirp.ID, chirp.CreatedAt, chirp.UpdatedAt, chirp.Body, chirp.UserID,
				})
				if err != nil {
					return
				}

				_, err = writer.Write(buffer.Bytes())
				if err != nil {
					return
				}
			}

		},
	)

	mux.HandleFunc(
		"GET /api/chirps",
		func(writer http.ResponseWriter, request *http.Request) {
			type tweet struct {
				ID        uuid.UUID `json:"id"`
				CreatedAt time.Time `json:"created_at"`
				UpdatedAt time.Time `json:"updated_at"`
				Body      string    `json:"body"`
				UserID    uuid.UUID `json:"user_id"`
			}

			f := func(c db.Chirp) tweet {
				return tweet{
					c.ID,
					c.CreatedAt,
					c.UpdatedAt,
					c.Body,
					c.UserID,
				}
			}

			var chirps []db.Chirp
			order := request.URL.Query().Get("sort")
			if author_id := request.URL.Query().Get("author_id"); author_id != "" {
				user_id, err := uuid.Parse(author_id)
				if err != nil {
					writer.WriteHeader(http.StatusBadRequest)
					writer.Write([]byte("Error: Invalid user id provided for author"))
					return
				}
				if order == "desc" {
					chirps, err = config.queries.GetChirpsForUserDesc(request.Context(), user_id)
				} else {
					chirps, err = config.queries.GetChirpsForUser(request.Context(), user_id)
				}
				if err != nil {
					writer.WriteHeader(http.StatusInternalServerError)
					return
				}
			} else {
				if order == "desc" {
					chirps, err = config.queries.GetChirpsDesc(request.Context())
				} else {
					chirps, err = config.queries.GetChirps(request.Context())
				}
				if err != nil {
					writer.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
			var results []tweet
			for _, chirp := range chirps {
				results = append(results, f(chirp))
			}

			marshal, err := json.Marshal(results)
			if err != nil {
				return
			}

			writer.WriteHeader(http.StatusOK)
			writer.Write(marshal)
		})

	mux.HandleFunc(
		"GET /api/chirps/{chirpID}",
		func(writer http.ResponseWriter, request *http.Request) {
			chirpId, err := uuid.Parse(request.PathValue("chirpID"))
			chirp, err := config.queries.GetChirp(request.Context(), chirpId)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					writer.WriteHeader(404)
				}
				return
			}

			type tweet struct {
				ID        uuid.UUID `json:"id"`
				CreatedAt time.Time `json:"created_at"`
				UpdatedAt time.Time `json:"updated_at"`
				Body      string    `json:"body"`
				UserID    uuid.UUID `json:"user_id"`
			}

			f := func(c db.Chirp) tweet {
				return tweet{
					c.ID,
					c.CreatedAt,
					c.UpdatedAt,
					c.Body,
					c.UserID,
				}
			}(chirp)

			marshal, _ := json.Marshal(f)
			if err != nil {
				return
			}

			writer.WriteHeader(200)
			writer.Write(marshal)
		},
	)

	mux.HandleFunc(
		"POST /api/login",
		func(respWriter http.ResponseWriter, req *http.Request) {
			body := struct {
				Password string `json:"password"`
				Email    string `json:"email"`
			}{}

			respWriter.Header().Add("Content-Type", "text/json")

			// JSON
			var buffer bytes.Buffer
			decoder := json.NewDecoder(req.Body)
			encoder := json.NewEncoder(&buffer)
			err := decoder.Decode(&body)
			if err != nil {
				respWriter.WriteHeader(400)
				err := encoder.Encode(struct {
					Error string `json:"error"`
				}{"Something went wrong"})
				if err != nil {
					return
				}

				_, err = respWriter.Write(buffer.Bytes())
				if err != nil {
					return
				}
			}

			// get user from DB
			user, err := config.queries.GetUserDetailsByEmail(req.Context(), sql.NullString{
				String: body.Email,
				Valid:  true,
			})
			if err != nil {
				respWriter.WriteHeader(401)
				_, err = respWriter.Write(bytes.NewBufferString("Incorrect email or password").Bytes())
				if err != nil {
					return
				}
			}

			// validate password
			err = auth.CheckPasswordHash(body.Password, user.HashedPassword)
			if err != nil {
				respWriter.WriteHeader(401)
				_, err = respWriter.Write(bytes.NewBufferString("Incorrect email or password" + err.Error()).Bytes())
				if err != nil {
					return
				}
			} else {
				// Valid User
				jwt, err := auth.MakeJWT(user.ID, config.jwtSecret, time.Hour*1)
				if err != nil {
					respWriter.WriteHeader(401)
					_, err = respWriter.Write(bytes.NewBufferString("Incorrect email or password" + err.Error()).Bytes())
					if err != nil {
						return
					}
				}

				refreshTokenStr, err := auth.MakeRefreshToken()
				if err != nil {
					respWriter.WriteHeader(500)
				}
				_, err = config.queries.AddRefreshToken(
					req.Context(),
					db.AddRefreshTokenParams{
						Token:     refreshTokenStr,
						UserID:    user.ID,
						ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
					},
				)
				if err != nil {
					respWriter.WriteHeader(500)
				}

				respWriter.WriteHeader(200)

				err = encoder.Encode(struct {
					ID           uuid.UUID `json:"id"`
					CreatedAt    time.Time `json:"created_at"`
					UpdatedAt    time.Time `json:"updated_at"`
					Email        string    `json:"email"`
					Token        string    `json:"token"`
					RefreshToken string    `json:"refresh_token"`
					IsChirpyRed  bool      `json:"is_chirpy_red"`
				}{
					ID:           user.ID,
					CreatedAt:    user.CreatedAt,
					UpdatedAt:    user.UpdatedAt,
					Email:        user.Email.String,
					Token:        jwt,
					RefreshToken: refreshTokenStr,
					IsChirpyRed:  user.IsChirpyRed.Valid && user.IsChirpyRed.Bool,
				})
				if err != nil {
					return
				}

				_, err = respWriter.Write(buffer.Bytes())
				if err != nil {
					return
				}

			}

		},
	)

	mux.HandleFunc(
		"POST /api/refresh",
		func(respWriter http.ResponseWriter, req *http.Request) {
			bearerToken, err := auth.GetBearerToken(req.Header)
			if err != nil {
				respWriter.WriteHeader(401)
			}

			refreshToken, err := config.queries.GetRefreshToken(req.Context(), bearerToken)
			if err != nil || refreshToken.ExpiresAt.Before(time.Now()) || (refreshToken.RevokedAt.Valid && refreshToken.RevokedAt.Time.Before(time.Now())) {
				respWriter.WriteHeader(401)
			}

			jwt, err := auth.MakeJWT(refreshToken.UserID, config.jwtSecret, time.Hour)
			if err != nil {
				respWriter.WriteHeader(500)
				_, err = respWriter.Write(bytes.NewBufferString("Error while creating token" + err.Error()).Bytes())
				if err != nil {
					return
				}
			}

			var buffer bytes.Buffer
			encoder := json.NewEncoder(&buffer)

			respWriter.WriteHeader(200)

			err = encoder.Encode(struct {
				Token string `json:"token"`
			}{
				Token: jwt,
			})
			if err != nil {
				return
			}

			_, err = respWriter.Write(buffer.Bytes())
			if err != nil {
				return
			}

		},
	)

	mux.HandleFunc(
		"POST /api/revoke",
		func(respWriter http.ResponseWriter, req *http.Request) {
			bearerToken, err := auth.GetBearerToken(req.Header)
			if err != nil {
				respWriter.WriteHeader(401)
				return
			}

			_, err = config.queries.GetRefreshToken(req.Context(), bearerToken)
			if err != nil {
				respWriter.WriteHeader(401)
				return
			}

			token, err := config.queries.RovokeToken(req.Context(), bearerToken)
			if err != nil || token != 1 {
				respWriter.WriteHeader(500)
				return
			}

			respWriter.WriteHeader(204)
		},
	)

	mux.HandleFunc(
		"DELETE /api/chirps/{chirpId}",
		func(writer http.ResponseWriter, request *http.Request) {
			chirpID, err := uuid.Parse(request.PathValue("chirpId"))
			if err != nil {

				writer.WriteHeader(http.StatusBadRequest)
				return
			}

			jwt, err := auth.GetBearerToken(request.Header)
			if err != nil {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}

			userId, err := auth.ValidateJWT(jwt, config.jwtSecret)
			if err != nil {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}

			chirp, err := config.queries.GetChirp(request.Context(), chirpID)
			if err != nil {
				writer.WriteHeader(http.StatusNotFound)
				return
			}

			if chirp.UserID != userId {
				writer.WriteHeader(http.StatusForbidden)
				return
			}

			err = config.queries.DeleteChirp(
				request.Context(),
				chirpID,
			)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}

			writer.WriteHeader(http.StatusNoContent)
		},
	)

	mux.HandleFunc(
		"POST /api/polka/webhooks",
		func(writer http.ResponseWriter, request *http.Request) {
			apiKey, err := auth.GetAPIKey(request.Header)
			if err != nil || apiKey != config.polkaKey {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}

			requestBody := struct {
				Event string `json:"event"`
				Data  struct {
					UserId uuid.UUID `json:"user_id"`
				} `json:"data"`
			}{}

			// JSON
			decoder := json.NewDecoder(request.Body)
			decoder.Decode(&requestBody)

			if requestBody.Event != "user.upgraded" {
				writer.WriteHeader(http.StatusNoContent)
				return
			}

			user, err := config.queries.GetUserDetailsById(request.Context(), requestBody.Data.UserId)
			if err != nil {
				writer.WriteHeader(http.StatusNotFound)
				return
			}

			count, err := config.queries.UpgradeToRed(request.Context(), user.ID)
			if err != nil || count != 1 {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}

			writer.WriteHeader(http.StatusNoContent)
		},
	)

	// Start Server
	err = server.ListenAndServe()
	if err != nil {
		return
	}
}

func validateChirp(chirp string) (string, error) {
	if len(chirp) <= 140 {
		bannedWords := []string{
			"kerfuffle",
			"sharbert",
			"fornax",
		}
		var result []string

		for _, word := range strings.Split(chirp, " ") {
			if slices.Contains(bannedWords, strings.ToLower(word)) {
				result = append(result, "****")
			} else {
				result = append(result, word)
			}
		}
		return strings.Join(result, " "), nil
	}
	return "", fmt.Errorf("chirp can't be more than 140 chars")
}
