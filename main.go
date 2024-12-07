package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"

	"time"

	_ "modernc.org/sqlite"
)

// секретный ключ
var secret = []byte("gBElG5NThZSye")

func createSignedToken(id, ip string) (string, error) {

	// создаём payload
	claims := jwt.MapClaims{
		"user_id": id,
		"user_ip": ip,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}

	// создаём jwt с методом шифрования HS512 и payload
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	// получаем подписанный токен
	signedToken, err := jwtToken.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign jwt: %s", err)
	}
	return signedToken, nil
}

func createRefreshToken() (string, error) {
	token := make([]byte, 32)

	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("failed to create refresh token: %s", err)
	}
	refreshToken := base64.StdEncoding.EncodeToString(token)

	return refreshToken, nil
}

func hashRefreshToken(token string) (string, error) {
	// хеширование Refresh токена
	hashToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(hashToken), err
}

func handlerCreateTokens(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("user_id")
	if userID == "0" || userID == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("userID missing"))
		return
	}

	ip := req.RemoteAddr

	accessToken, err := createSignedToken(userID, ip)
	if err != nil {
		http.Error(w, "failed to create access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := createRefreshToken()
	if err != nil {
		http.Error(w, "failed to create refresh token", http.StatusInternalServerError)
		return
	}

	hashedRefreshToken, _ := hashRefreshToken(refreshToken)

	insertHashedToken(userID, hashedRefreshToken)

	json.NewEncoder(w).Encode(map[string]string{
		"accessToken":  accessToken,
		"refreshToken": hashedRefreshToken,
	})

	//w.Write([]byte(accessToken))
}

func handlerRefreshToken(w http.ResponseWriter, req *http.Request) {
	token := req.URL.Query().Get("token_hash")

	userID := req.URL.Query().Get("user_id")
	if userID == "0" || userID == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("user_id missing"))
		return
	}

	var tokenDB string
	// Вытаскиваем из базы хэшированный токен и проверяем его
	db, err := sql.Open("sqlite", "data_hh.db")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	row := db.QueryRow("SELECT token_hash FROM refresh_tokens WHERE user_id = :user_id", sql.Named("user_id", userID))
	err = row.Scan(&tokenDB)
	if err != nil {
		fmt.Println("problem", err)
		return
	}

	// Если хэши совпадают, генерируем новые токены
	if token == tokenDB {
		w.Write([]byte("Ваш новый токен:"))

		ip := req.RemoteAddr

		accessToken, err := createSignedToken(userID, ip)
		if err != nil {
			http.Error(w, "failed to create access token", http.StatusInternalServerError)
			return
		}

		refreshToken, err := createRefreshToken()
		if err != nil {
			http.Error(w, "failed to create refresh token", http.StatusInternalServerError)
			return
		}

		hashedRefreshToken, _ := hashRefreshToken(refreshToken)

		updateHashedToken(userID, hashedRefreshToken)

		json.NewEncoder(w).Encode(map[string]string{
			"accessToken":  accessToken,
			"refreshToken": hashedRefreshToken,
		})
	} else {
		w.Write([]byte("Доступ запрещен, токены не совпадают"))
	}
}

func updateHashedToken(userID, hashToken string) {
	db, err := sql.Open("sqlite", "data_hh.db")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	_, err = db.Exec("UPDATE refresh_tokens SET token_hash = :token_hash WHERE user_id = :user_id",
		sql.Named("token_hash", hashToken),
		sql.Named("user_id", userID))
	if err != nil {
		fmt.Println(err)
		return
	}

}

func insertHashedToken(userID, hashToken string) {
	db, err := sql.Open("sqlite", "data_hh.db")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO refresh_tokens (token_hash, user_id) VALUES (:token_hash, :user_id)",
		sql.Named("token_hash", hashToken),
		sql.Named("user_id", userID))
	if err != nil {
		fmt.Println(err)
		return
	}

}

func main() {
	db, err := sql.Open("sqlite", "data_hh.db")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()
	//db.Query("DELETE FROM refresh_tokens")

	rows, err := db.Query("SELECT user_id, token_hash FROM refresh_tokens")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var x, y string

		err := rows.Scan(&x, &y)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(x, y)
	}
	//fmt.Println(tokenHash)
	r := mux.NewRouter()
	r.HandleFunc("/tokens", handlerCreateTokens).Methods("POST")
	r.HandleFunc("/refresh", handlerRefreshToken).Methods("POST")
	http.ListenAndServe(":8080", r)

}
