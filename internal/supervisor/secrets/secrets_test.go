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
	ring, err := OpenKeyring(cfg, fixedFilePrompt())
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
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

func TestReload_AddedUpdatedRemoved(t *testing.T) {
	scrubEnv(t, "EXA_API_KEY", "FIRECRAWL_KEY", "LINEAR_TOKEN")
	cfg := seedFileKeyring(t, []string{"EXA_API_KEY", "FIRECRAWL_KEY", "LINEAR_"}, map[string]string{
		"EXA_API_KEY":  "v1",
		"LINEAR_TOKEN": "tok-v1",
	})
	loader := NewLoader(fixedFilePrompt())
	if _, err := loader.LoadAll(context.Background(), cfg); err != nil {
		t.Fatalf("initial LoadAll: %v", err)
	}
	if os.Getenv("EXA_API_KEY") != "v1" {
		t.Fatalf("setup: EXA_API_KEY = %q, want v1", os.Getenv("EXA_API_KEY"))
	}

	// Mutate the keyring underneath the loader.
	ring, err := OpenKeyring(cfg, fixedFilePrompt())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: "EXA_API_KEY", Data: []byte("v2")}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: "FIRECRAWL_KEY", Data: []byte("new")}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := ring.Remove("LINEAR_TOKEN"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	rr, err := loader.Reload(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if os.Getenv("EXA_API_KEY") != "v2" {
		t.Errorf("after reload: EXA_API_KEY = %q, want v2", os.Getenv("EXA_API_KEY"))
	}
	if os.Getenv("FIRECRAWL_KEY") != "new" {
		t.Errorf("after reload: FIRECRAWL_KEY = %q, want new", os.Getenv("FIRECRAWL_KEY"))
	}
	if v, ok := os.LookupEnv("LINEAR_TOKEN"); ok {
		t.Errorf("after reload: LINEAR_TOKEN = %q (still set), want unset", v)
	}

	if !contains(rr.Updated, "EXA_API_KEY") {
		t.Errorf("Updated = %v, want to contain EXA_API_KEY", rr.Updated)
	}
	if !contains(rr.Added, "FIRECRAWL_KEY") {
		t.Errorf("Added = %v, want to contain FIRECRAWL_KEY", rr.Added)
	}
	if !contains(rr.Removed, "LINEAR_TOKEN") {
		t.Errorf("Removed = %v, want to contain LINEAR_TOKEN", rr.Removed)
	}
}

func TestReload_Idempotent(t *testing.T) {
	scrubEnv(t, "EXA_API_KEY")
	cfg := seedFileKeyring(t, []string{"EXA_API_KEY"}, map[string]string{
		"EXA_API_KEY": "v1",
	})
	loader := NewLoader(fixedFilePrompt())
	if _, err := loader.LoadAll(context.Background(), cfg); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	rr, err := loader.Reload(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(rr.Added)+len(rr.Updated)+len(rr.Removed) != 0 {
		t.Errorf("idempotent reload had changes: %+v", rr)
	}
}

func TestNames(t *testing.T) {
	scrubEnv(t, "EXA_API_KEY", "LINEAR_TOKEN")
	cfg := seedFileKeyring(t, []string{"EXA_API_KEY", "LINEAR_TOKEN"}, map[string]string{
		"EXA_API_KEY":  "v",
		"LINEAR_TOKEN": "v",
	})
	loader := NewLoader(fixedFilePrompt())
	if got := loader.Names(); len(got) != 0 {
		t.Errorf("Names() before LoadAll = %v, want empty", got)
	}
	if _, err := loader.LoadAll(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got := loader.Names()
	want := []string{"EXA_API_KEY", "LINEAR_TOKEN"}
	if !equalStringSlices(got, want) {
		t.Errorf("Names() after LoadAll = %v, want %v", got, want)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

