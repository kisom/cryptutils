package sync

// Response is returned by the server for each request. If success is
// false, Message will contain an error message. Otherwise, Result
// contains the data returned from the server.
type Response struct {
	Success bool              `json:"success"`
	Message string            `json:"message"`
	Result  map[string]string `json:"result"`
}
