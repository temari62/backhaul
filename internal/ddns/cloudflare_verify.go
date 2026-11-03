package ddns

import (
	"context"
	"net/http"
)

// CloudflareVerifyToken asks Cloudflare whether token is valid, through the
// endpoint any user API token may call on itself (no permissions needed). It
// returns the token's status ("active", "expired", "disabled"); an error
// means Cloudflare did not accept the token at all. Used to turn an opaque
// "Invalid access token" on a real request into a definite verdict.
func CloudflareVerifyToken(ctx context.Context, client *http.Client, token string) (string, error) {
	c := &Cloudflare{o: Options{Token: token, Client: orDefault(client)}, BaseURL: CloudflareAPI}
	var res struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, http.MethodGet, "/user/tokens/verify", nil, &res); err != nil {
		return "", err
	}
	return res.Status, nil
}
