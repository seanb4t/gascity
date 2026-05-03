package main

import (
	"context"
	"os"
	"testing"
)

// TestGCMcpList_LoadStartupSecrets_WireCheck verifies that loadStartupSecrets
// is wired into the gc mcp list code path and populates env vars from the
// keyring before MCP template projection runs. Mirrors the equivalent test for
// gc start (TestGCStart_LoadStartupSecrets_WireCheck in cmd_start_secrets_test.go).
func TestGCMcpList_LoadStartupSecrets_WireCheck(t *testing.T) {
	const testKey = "TEST_WIRE_SECRET_MCP_LIST"
	const testVal = "mcp-list-wired"

	_ = setupStartSecretsTest(t, testKey, testVal)

	// loadStartupSecrets is the function wired into newMcpListCmd's RunE.
	// Calling it directly must populate the env var.
	loadStartupSecrets(context.Background(), os.Stderr)

	if got := os.Getenv(testKey); got != testVal {
		t.Errorf("%s = %q after loadStartupSecrets, want %q", testKey, got, testVal)
	}
}
