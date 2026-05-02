package secrets

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/99designs/keyring"
	"github.com/gastownhall/gascity/internal/supervisor"
)

// seedFileKeyring populates a fresh file-backend keyring with the
// given items and returns the SecretsConfig pointed at it.
func seedFileKeyring(t *testing.T, prefixes []string, items map[string]string) supervisor.SecretsConfig {
	t.Helper()
	cfg := fileBackendConfig(t, prefixes)
	ring, err := openKeyring(cfg, fixedFilePrompt())
	if err != nil {
		t.Fatalf("openKeyring: %v", err)
	}
	for k, v := range items {
		if err := ring.Set(keyring.Item{Key: k, Data: []byte(v)}); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}
	return cfg
}

// scrubEnv removes test-set env vars after the test.
func scrubEnv(t *testing.T, names ...string) {
	t.Helper()
	t.Cleanup(func() {
		for _, n := range names {
			os.Unsetenv(n)
		}
	})
}

func TestLoadAll_EmptyKeyring(t *testing.T) {
	cfg := seedFileKeyring(t, []string{"EXA_API_KEY"}, nil)
	loader := NewLoader(fixedFilePrompt())
	res, err := loader.LoadAll(context.Background(), cfg)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(res.Set) != 0 {
		t.Errorf("Set = %v, want empty", res.Set)
	}
	if len(res.Missing) != 1 || res.Missing[0] != "EXA_API_KEY" {
		t.Errorf("Missing = %v, want [EXA_API_KEY]", res.Missing)
	}
}

func TestLoadAll_ExactMatch(t *testing.T) {
	scrubEnv(t, "EXA_API_KEY")
	cfg := seedFileKeyring(t, []string{"EXA_API_KEY"}, map[string]string{
		"EXA_API_KEY": "sk-real",
	})
	loader := NewLoader(fixedFilePrompt())
	res, err := loader.LoadAll(context.Background(), cfg)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if v := os.Getenv("EXA_API_KEY"); v != "sk-real" {
		t.Errorf("EXA_API_KEY env = %q, want sk-real", v)
	}
	if len(res.Set) != 1 || res.Set[0] != "EXA_API_KEY" {
		t.Errorf("Set = %v, want [EXA_API_KEY]", res.Set)
	}
	if len(res.Missing) != 0 {
		t.Errorf("Missing = %v, want empty", res.Missing)
	}
}

func TestLoadAll_PrefixMatchesMultiple(t *testing.T) {
	scrubEnv(t, "LINEAR_TOKEN", "LINEAR_REFRESH_TOKEN")
	cfg := seedFileKeyring(t, []string{"LINEAR_"}, map[string]string{
		"LINEAR_TOKEN":         "tok-1",
		"LINEAR_REFRESH_TOKEN": "tok-2",
		"OTHER_KEY":            "ignored",
	})
	loader := NewLoader(fixedFilePrompt())
	res, err := loader.LoadAll(context.Background(), cfg)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if os.Getenv("LINEAR_TOKEN") != "tok-1" || os.Getenv("LINEAR_REFRESH_TOKEN") != "tok-2" {
		t.Errorf("env vars not set correctly: TOKEN=%q REFRESH=%q",
			os.Getenv("LINEAR_TOKEN"), os.Getenv("LINEAR_REFRESH_TOKEN"))
	}
	if os.Getenv("OTHER_KEY") != "" {
		t.Errorf("OTHER_KEY env = %q, want empty (not in prefix)", os.Getenv("OTHER_KEY"))
	}
	sort.Strings(res.Set)
	want := []string{"LINEAR_REFRESH_TOKEN", "LINEAR_TOKEN"}
	if !equalStringSlices(res.Set, want) {
		t.Errorf("Set = %v, want %v", res.Set, want)
	}
}

func TestLoadAll_EmptyValueSkipped(t *testing.T) {
	scrubEnv(t, "FIRECRAWL_KEY")
	cfg := seedFileKeyring(t, []string{"FIRECRAWL_KEY"}, map[string]string{
		"FIRECRAWL_KEY": "",
	})
	loader := NewLoader(fixedFilePrompt())
	res, err := loader.LoadAll(context.Background(), cfg)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if v := os.Getenv("FIRECRAWL_KEY"); v != "" {
		t.Errorf("FIRECRAWL_KEY = %q, want empty (skipped)", v)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "FIRECRAWL_KEY" {
		t.Errorf("Skipped = %v, want [FIRECRAWL_KEY]", res.Skipped)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

