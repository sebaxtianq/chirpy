package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/joho/godotenv"

	"github.com/sebaxtianq/chirpy/internal/auth"
	"github.com/sebaxtianq/chirpy/internal/database"

	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	token          string
}

func (cfg *apiConfig) middlewareMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
		w.Header().Set("Cache-Control", "no-cache")
	})

}
func (c *apiConfig) num_requests(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf(`
	<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`,
		c.fileserverHits.Load())))
}

func (c *apiConfig) reset_all(w http.ResponseWriter, r *http.Request) {
	platform := os.Getenv("PLATFORM")
	if platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Println("Unauthorized to access this endpoint")
		return
	}
	w.WriteHeader(http.StatusOK)
	c.fileserverHits.Store(0)
	_, err := c.db.DeleteUsers(r.Context())
	if err != nil {
		fmt.Println("Error deleting users from database", err)
	}
}

func (c *apiConfig) create_user(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type return_vals struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Email      string    `json:"email"`
	}
	params := parameters{}
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		fmt.Println("Error decoding json from body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	params.Password, err = auth.HashPassword(params.Password)
	if err != nil {
		fmt.Print("Error hashing the password")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user, err := c.db.CreateUser(r.Context(), database.CreateUserParams{params.Email, params.Password})
	if err != nil {
		fmt.Println("Error de conexion a la base de datos", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	norm_user := return_vals{
		Id:         user.ID,
		Created_at: user.CreatedAt,
		Updated_at: user.UpdatedAt,
		Email:      user.Email,
	}
	res, err := json.Marshal(norm_user)
	if err != nil {
		fmt.Println("Error codificando payload en json:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write(res)
}

func (c *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type return_vals struct {
		Id            uuid.UUID `json:"id"`
		Created_at    time.Time `json:"created_at"`
		Updated_at    time.Time `json:"updated_at"`
		Email         string    `json:"email"`
		Token         string    `json:"token"`
		Refresh_token string    `json:"refresh_token"`
	}
	token_duration := time.Second * 3600
	refresh_token_duration := 60 * 24 * time.Hour
	params := parameters{}
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		fmt.Print("Couldn't decode json parameters", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user, err := c.db.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		fmt.Print("Incorrect email or password", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	valid, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		fmt.Print("Incorrect email or password", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !valid {
		fmt.Print("Incorrect email or password", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	godotenv.Load()
	server_token := os.Getenv("JWT_TOKEN")
	token, err := auth.MakeJWT(user.ID, server_token, token_duration)
	if err != nil {
		fmt.Print("Error generating JWT token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	refresh_token := auth.MakeRefreshToken()
	_, err = c.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{refresh_token, user.ID, time.Now().Add(refresh_token_duration)})
	if err != nil {
		fmt.Print("Error writing refresh token to database")
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	resp_body := return_vals{
		Id:            user.ID,
		Created_at:    user.CreatedAt,
		Updated_at:    user.UpdatedAt,
		Email:         user.Email,
		Token:         token,
		Refresh_token: refresh_token,
	}
	dat, err := json.Marshal(resp_body)
	w.Write(dat)
}

func (c *apiConfig) get_chirps(w http.ResponseWriter, r *http.Request) {
	type return_vals struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Body       string    `json:"body"`
		User_id    uuid.UUID `json:"user_id"`
	}
	chirps, err := c.db.ReadChirps(r.Context())
	if err != nil {
		fmt.Print("Error reading from database: ", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp_body := []return_vals{}
	for _, chirp := range chirps {
		resp_body = append(resp_body, return_vals{
			Id:         chirp.ID,
			Created_at: chirp.CreatedAt,
			Updated_at: chirp.UpdatedAt,
			Body:       chirp.Body,
			User_id:    chirp.UserID,
		})
	}
	dat, err := json.Marshal(resp_body)
	w.Write(dat)
}

func (c *apiConfig) get_chirp(w http.ResponseWriter, r *http.Request) {
	ChirpID := r.PathValue("ChirpID")
	if ChirpID == "" {
		fmt.Print("Error: Chirp ID not found")
		w.WriteHeader(400)
		return
	}
	ChirpUUID, err := uuid.Parse(ChirpID)
	if err != nil {
		fmt.Printf("Error: Could not parse Chirp UUID : %s got error %v", ChirpID, err)
		w.WriteHeader(400)
		return
	}
	type return_vals struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Body       string    `json:"body"`
		User_id    uuid.UUID `json:"user_id"`
	}
	chirp, err := c.db.ReadChirp(r.Context(), ChirpUUID)
	if err != nil {
		fmt.Print("Chirp not found", err)
		w.WriteHeader(404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp_body := return_vals{
		Id:         chirp.ID,
		Created_at: chirp.CreatedAt,
		Updated_at: chirp.UpdatedAt,
		Body:       chirp.Body,
		User_id:    chirp.UserID,
	}
	dat, err := json.Marshal(resp_body)
	w.Write(dat)
}

func (c *apiConfig) create_chirp(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body    string    `json:"body"`
		User_id uuid.UUID `json:"user_id"`
	}
	type return_vals struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Body       string    `json:"body"`
		User_id    uuid.UUID `json:"user_id"`
	}
	godotenv.Load()
	server_token := os.Getenv("JWT_TOKEN")
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	resp_body := return_vals{}
	if err != nil {
		fmt.Println("Error decoding json from body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token_usr, err := auth.ValidateJWT(token, server_token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	params.User_id = token_usr
	if len(params.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		return
	} else {
		chirp, err := c.db.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   params.Body,
			UserID: params.User_id,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println("Error while creating Chirp in database ", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp_body = return_vals{
			Id:         chirp.ID,
			Created_at: chirp.CreatedAt,
			Updated_at: chirp.UpdatedAt,
			Body:       chirp.Body,
			User_id:    chirp.UserID,
		}
		dat, err := json.Marshal(resp_body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println("Error Marshaling response")
			return
		}
		fmt.Println(dat)
		w.Write(dat)
	}

}

func main() {
	var cfg apiConfig
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	//server_token := os.Getenv("JWT_TOKEN")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println("Error opening postgres DB", err)
	}
	dbQueries := database.New(db)
	cfg.db = dbQueries
	defer db.Close()
	mux := http.NewServeMux()
	mux.Handle("/app/", cfg.middlewareMetrics(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.Handle("/app/assets/logo.png", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("GET /admin/metrics", cfg.num_requests)
	mux.HandleFunc("POST /admin/reset", cfg.reset_all)
	mux.HandleFunc("POST /api/chirps", cfg.create_chirp)
	mux.HandleFunc("GET /api/chirps", cfg.get_chirps)
	mux.HandleFunc("GET /api/chirps/{ChirpID}", cfg.get_chirp)
	mux.HandleFunc("POST /api/users", cfg.create_user)
	mux.HandleFunc("POST /api/login", cfg.login)
	serv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	serv.ListenAndServe()

}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(http.StatusText(http.StatusOK)))
}
