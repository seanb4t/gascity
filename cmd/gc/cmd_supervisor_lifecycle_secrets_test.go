package main

import (
	"context"
	"os"
	"testing"

	"github.com/gastownhall/gascity/internal/supervisor"
	"github.com/gastownhall/gascity/internal/supervisor/secrets"
)

// TestRunSupervisor_LoadsSecretsBeforeAPIBind exercises the loader
// in isolation to catch wiring errors. The full integration is
// covered by the integration test in test/integration/secrets_integration_test.go.
func TestRunSupervisor_LoadsSecretsBeforeAPIBind(t *testing.T) {
	if v, ok := os.LookupEnv("EXA_API_KEY"); ok {
		t.Cleanup(func() { os.Setenv("EXA_API_KEY", v) }) //nolint:errcheck,tenv
	} else {
		t.Cleanup(func() { os.Unsetenv("EXA_API_KEY") }) //nolint:tenv
	}
	os.Unsetenv("EXA_API_KEY") //nolint:tenv

	t.Setenv("GC_HOME", t.TempDir())
	t.Setenv(secrets.EnvPassphraseVar, "test-pw")

	storeDir := t.TempDir()
	cfg := supervisor.SecretsConfig{
		Age: supervisor.AgeBackendConfig{
			Dir:  storeDir,
			Keys: []string{"EXA_API_KEY"},
		},
	}

	store, err := secrets.Open(cfg.Age)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.Set("EXA_API_KEY", []byte("from-secrets")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	loader := secrets.NewLoader()
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

func TestSecretsReload_RoundTrip(t *testing.T) {
	if v, ok := os.LookupEnv("EXA_API_KEY"); ok {
		t.Cleanup(func() { os.Setenv("EXA_API_KEY", v) }) //nolint:errcheck,tenv
	} else {
		t.Cleanup(func() { os.Unsetenv("EXA_API_KEY") }) //nolint:tenv
	}
	os.Unsetenv("EXA_API_KEY") //nolint:tenv

	t.Setenv("GC_HOME", t.TempDir())
	t.Setenv(secrets.EnvPassphraseVar, "pw")

	storeDir := t.TempDir()
	cfg := supervisor.SecretsConfig{
		Age: supervisor.AgeBackendConfig{
			Dir:  storeDir,
			Keys: []string{"EXA_API_KEY"},
		},
	}
	loader := secrets.NewLoader()

	store, err := secrets.Open(cfg.Age)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("EXA_API_KEY", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.LoadAll(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("EXA_API_KEY") != "v1" {
		t.Fatal("setup")
	}

	if err := store.Set("EXA_API_KEY", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	rr, err := loader.Reload(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if os.Getenv("EXA_API_KEY") != "v2" {
		t.Errorf("EXA_API_KEY = %q, want v2", os.Getenv("EXA_API_KEY"))
	}
	if !reloadContains(rr.Updated, "EXA_API_KEY") {
		t.Errorf("Updated = %v, want EXA_API_KEY", rr.Updated)
	}
}

// reloadContains is a local string-slice contains helper; named to
// avoid colliding with any same-named helper in other test files.
func reloadContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
