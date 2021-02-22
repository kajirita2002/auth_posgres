package utils

import (
	"encoding/json"
	"net/http"

	"github.com/kaji2002/auth_posgres/entity"
)

func ErrorInResponse(w http.ResponseWriter, status int, error entity.Error) {
	w.WriteHeader(status) // 400 とか 500 などの HTTP status コードが入る
	json.NewEncoder(w).Encode(error)
	return
}

func ResponseByJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
	return
}
