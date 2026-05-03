package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gastownhall/gascity/internal/supervisor/secrets"
)

// SecretStatus describes one env var the supervisor has loaded from
// its configured secrets backend. The actual value is NEVER included.
type SecretStatus struct {
	Name   string `json:"name" doc:"env var name"`
	Length int    `json:"length" doc:"byte length of the value"`
	SHA256 string `json:"sha256" doc:"hex-encoded SHA-256 of the value (for drift comparison)"`
}

// SupervisorSecretsStatusInput is the input for GET /v1/supervisor/secrets/status.
type SupervisorSecretsStatusInput struct{}

// SupervisorSecretsStatusResponse is the response body for GET /v1/supervisor/secrets/status.
type SupervisorSecretsStatusResponse struct {
	Secrets []SecretStatus `json:"secrets"`
}

// SupervisorSecretsStatusOutput is the Huma output for GET /v1/supervisor/secrets/status.
type SupervisorSecretsStatusOutput struct {
	Body SupervisorSecretsStatusResponse
}

// RegisterSupervisorSecretsStatus registers the GET /v1/supervisor/secrets/status endpoint.
// secretsView returns the names of currently-loaded secrets (as known to the
// supervisor's secrets.Loader). Values are read fresh from os.Environ for
// hashing; the loader doesn't keep them in memory.
func RegisterSupervisorSecretsStatus(api huma.API, secretsView func() []string) {
	huma.Register(api, huma.Operation{
		OperationID: "supervisor-secrets-status",
		Method:      "GET",
		Path:        "/v1/supervisor/secrets/status",
		Summary:     "List loaded supervisor secrets (names and hashes only)",
	}, func(ctx context.Context, _ *SupervisorSecretsStatusInput) (*SupervisorSecretsStatusOutput, error) {
		names := secretsView()
		sort.Strings(names)
		out := &SupervisorSecretsStatusOutput{}
		for _, name := range names {
			val := os.Getenv(name)
			if val == "" {
				continue
			}
			sum := sha256.Sum256([]byte(val))
			out.Body.Secrets = append(out.Body.Secrets, SecretStatus{
				Name:   name,
				Length: len(val),
				SHA256: hex.EncodeToString(sum[:]),
			})
		}
		return out, nil
	})
}

// SecretsLoaderView returns a closure that reports the names the loader
// set on its most recent LoadAll/Reload. Convenience for wiring at startup.
func SecretsLoaderView(loader *secrets.Loader) func() []string {
	return func() []string {
		return loader.Names()
	}
}
