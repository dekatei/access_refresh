package main

import (
	"net/http"
	"net/http/httptest"

	//"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateHandlerWhenOk(t *testing.T) {
	req := httptest.NewRequest("GET", "/tokens?user_id=1", nil)

	responseRecorder := httptest.NewRecorder()
	handler := http.HandlerFunc(handlerCreateTokens)
	handler.ServeHTTP(responseRecorder, req)

	status := responseRecorder.Code
	require.Equal(t, http.StatusOK, status)

	body := responseRecorder.Body.String()
	assert.NotEmpty(t, body)
}

func TestCreateHandlerWhenMissedUserID(t *testing.T) {
	req := httptest.NewRequest("POST", "/tokens", nil)

	responseRecorder := httptest.NewRecorder()
	handler := http.HandlerFunc(handlerCreateTokens)
	handler.ServeHTTP(responseRecorder, req)

	status := responseRecorder.Code
	require.Equal(t, http.StatusBadRequest, status)

}
