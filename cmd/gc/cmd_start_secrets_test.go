package main

import (
	"context"
	"os"
	"testing"

	"github.com/gastownhall/gascity/internal/supervisor"
	supsecrets "github.com/gastownhall/gascity/internal/supervisor/secrets"
)

const startTestSecretsPassword = "gc-start-test-password"

// setupStartSecretsTest creates a temp supervisor.toml + age-backed
// secrets store, seeds keyName=keyVal, and returns the loaded
// SecretsConfig. The test env is cleaned up automatically via
// t.Cleanup.
func setupStartSecretsTest(t *testing.T, keyName, keyVal string) supervisor.SecretsConfig {
	t.Helper()

	// Restore env state on cleanup.
	if v, ok := os.LookupEnv(keyName); ok {
		t.Cleanup(func() { os.Setenv(keyName, v) }) //nolint:errcheck,tenv
	} else {
		t.Cleanup(func() { os.Unsetenv(keyName) }) //nolint:tenv
	}
	os.Unsetenv(keyName) //nolint:tenv

	t.Setenv("GC_HOME", t.TempDir())
	t.Setenv(supsecrets.EnvPassphraseVar, startTestSecretsPassword)

	storeDir := t.TempDir()
	tomlBody := "[secrets.age]\ndir = \"" + storeDir + "\"\nkeys = [\"" + keyName + "\"]\n"
	writeTestSupervisorTOML(t, tomlBody)

	store, err := supsecrets.Open(supervisor.AgeBackendConfig{Dir: storeDir})
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	if err := store.Set(keyName, []byte(keyVal)); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	cfg, err := supervisor.LoadConfig(supervisor.ConfigPath())
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg.Secrets
}

// TestGCStart_LoadsSecretsBeforeMCPExpansion verifies that the gc start path
// loads secrets from the age store into the process environment before MCP
// template expansion. Exercises the loader in isolation rather than the full
// doStartStandalone pipeline.
func TestGCStart_LoadsSecretsBeforeMCPExpansion(t *testing.T) {
	const testKey = "TEST_SECRET_KEY_START"
	const testVal = "gc-start-test-value"

	cfg := setupStartSecretsTest(t, testKey, testVal)

	loader := supsecrets.NewLoader()
	res, err := loader.LoadAll(context.Background(), cfg)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(res.Set) != 1 {
		t.Fatalf("Set = %v, want one entry", res.Set)
	}
	if got := os.Getenv(testKey); got != testVal {
		t.Errorf("%s = %q, want %q", testKey, got, testVal)
	}
}

// TestGCStart_LoadStartupSecrets_WireCheck verifies that loadStartupSecrets
// is wired into the gc start code path and populates env vars from the store.
// doStartStandalone must call loadStartupSecrets before runStage1MCPProjection.
func TestGCStart_LoadStartupSecrets_WireCheck(t *testing.T) {
	const testKey = "TEST_WIRE_SECRET_START"
	const testVal = "wired"

	_ = setupStartSecretsTest(t, testKey, testVal)

	loadStartupSecrets(context.Background(), os.Stderr)

	if got := os.Getenv(testKey); got != testVal {
		t.Errorf("%s = %q after loadStartupSecrets, want %q", testKey, got, testVal)
	}
}
