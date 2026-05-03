package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSupervisorSecretsStatus_PayloadShape(t *testing.T) {
	statuses := []SecretStatus{
		{Name: "EXA_API_KEY", Length: 11, SHA256: hexsha("hello-world")},
		{Name: "LINEAR_TOKEN", Length: 7, SHA256: hexsha("abc1234")},
	}
	out := SupervisorSecretsStatusOutput{Body: SupervisorSecretsStatusResponse{Secrets: statuses}}

	blob := mustMarshal(t, out)
	for _, val := range []string{"hello-world", "abc1234"} {
		if strings.Contains(blob, val) {
			t.Errorf("payload contains secret value %q:\n%s", val, blob)
		}
	}
	for _, want := range []string{"EXA_API_KEY", "LINEAR_TOKEN", hexsha("hello-world")} {
		if !strings.Contains(blob, want) {
			t.Errorf("payload missing %q:\n%s", want, blob)
		}
	}
}

func hexsha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
