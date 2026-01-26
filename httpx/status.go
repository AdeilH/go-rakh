package httpx

import "net/http"

const (
	StatusOK                  = http.StatusOK                  // Successful request
	StatusCreated             = http.StatusCreated             // Resource created
	StatusNoContent           = http.StatusNoContent           // Successful with no body
	StatusBadRequest          = http.StatusBadRequest          // Validation or malformed input
	StatusUnauthorized        = http.StatusUnauthorized        // Missing or invalid authentication
	StatusForbidden           = http.StatusForbidden           // Authenticated but lacks permission
	StatusNotFound            = http.StatusNotFound            // Resource not found
	StatusConflict            = http.StatusConflict            // Uniqueness or version conflict
	StatusUnprocessableEntity = http.StatusUnprocessableEntity // Semantically invalid input
	StatusTooManyRequests     = http.StatusTooManyRequests     // Rate limiting or quotas
	StatusInternalError       = http.StatusInternalServerError // Unexpected server error
	StatusServiceUnavailable  = http.StatusServiceUnavailable  // Dependency failure or maintenance
)
