package main

import (
	"context"
	"os"
	"testing"

	"github.com/99designs/keyring"
	"github.com/gastownhall/gascity/internal/supervisor"
	"github.com/gastownhall/gascity/internal/supervisor/secrets"
)

// TestRunSupervisor_LoadsSecretsBeforeAPIBind exercises the loader
// in isolation to catch wiring errors. The full integration is
// covered by Task 15's integration tests.
func TestRunSupervisor_LoadsSecretsBeforeAPIBind(t *testing.T) {
	if v, ok := os.LookupEnv("EXA_API_KEY"); ok {
		t.Cleanup(func() { os.Setenv("EXA_API_KEY", v) })    //nolint:errcheck,tenv
	} else {
		t.Cleanup(func() { os.Unsetenv("EXA_API_KEY") }) //nolint:tenv
	}
	os.Unsetenv("EXA_API_KEY") //nolint:tenv

	cfg := supervisor.SecretsConfig{
		Backend: "file",
		File: supervisor.FileBackendConfig{
			Dir:      t.TempDir(),
			Prefixes: []string{"EXA_API_KEY"},
		},
	}
	promptFn := func(_ string) (string, error) { return "test-pw", nil }

	// Seed the file backend.
	ring, err := keyring.Open(keyring.Config{
		ServiceName:      "gc-supervisor",
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          cfg.File.Dir,
		FilePasswordFunc: promptFn,
	})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: "EXA_API_KEY", Data: []byte("from-secrets")}); err != nil {
		t.Fatalf("seed set: %v", err)
	}

	loader := secrets.NewLoader(promptFn)
	res, err := loader.LoadAll(context.Background(), cfg)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(res.Set) != 1 {
		t.Fatalf("Set = %v, want one entry", res.Set)
	}
	if got := os.Getenv("EXA_API_KEY"); got != "from-secrets" {
		t.Errorf("EXA_API_KEY env = %q, want from-secrets", got)
	}
}
