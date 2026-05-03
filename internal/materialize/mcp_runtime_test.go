package materialize

import (
	"testing"

	"github.com/gastownhall/gascity/internal/config"
)

// TestMCPTemplateData_BridgesAllowEnvOverrideFromProcessEnv verifies that
// MCPTemplateData honors cfg.AgentDefaults.AllowEnvOverride by pulling
// values from os.Environ() for whitelisted keys not already in agent.Env.
//
// This implements the city.toml comment's documented intent that
// allow_env_override propagates shell env vars into MCP template context.
func TestMCPTemplateData_BridgesAllowEnvOverrideFromProcessEnv(t *testing.T) {
	t.Setenv("BRIDGE_TEST_KEY", "from-process-env")
	t.Setenv("BRIDGE_OTHER_KEY", "should-not-leak")

	cfg := &config.City{
		AgentDefaults: config.AgentDefaults{
			AllowEnvOverride: []string{"BRIDGE_TEST_KEY"},
		},
	}
	agent := &config.Agent{Name: "dog"}

	data := MCPTemplateData(cfg, "/tmp/city", agent, "dog", "/tmp/work")

	if got := data["BRIDGE_TEST_KEY"]; got != "from-process-env" {
		t.Errorf("data[BRIDGE_TEST_KEY] = %q, want %q", got, "from-process-env")
	}
	if _, leaked := data["BRIDGE_OTHER_KEY"]; leaked {
		t.Errorf("data leaked BRIDGE_OTHER_KEY (not in AllowEnvOverride)")
	}
}

// TestMCPTemplateData_AgentEnvWinsOverProcessEnv verifies the precedence:
// per-agent env values are NOT overwritten by os.Environ values, even if
// the key is in AllowEnvOverride.
func TestMCPTemplateData_AgentEnvWinsOverProcessEnv(t *testing.T) {
	t.Setenv("PRECEDENCE_KEY", "from-process-env")

	cfg := &config.City{
		AgentDefaults: config.AgentDefaults{
			AllowEnvOverride: []string{"PRECEDENCE_KEY"},
		},
	}
	agent := &config.Agent{
		Name: "dog",
		Env:  map[string]string{"PRECEDENCE_KEY": "from-agent-env"},
	}

	data := MCPTemplateData(cfg, "/tmp/city", agent, "dog", "/tmp/work")

	if got := data["PRECEDENCE_KEY"]; got != "from-agent-env" {
		t.Errorf("data[PRECEDENCE_KEY] = %q, want %q (agent env wins)", got, "from-agent-env")
	}
}

// TestMCPTemplateData_EmptyEnvNotBridged verifies we don't pollute the
// template context with empty strings.
func TestMCPTemplateData_EmptyEnvNotBridged(t *testing.T) {
	t.Setenv("EMPTY_BRIDGE_KEY", "")

	cfg := &config.City{
		AgentDefaults: config.AgentDefaults{
			AllowEnvOverride: []string{"EMPTY_BRIDGE_KEY"},
		},
	}
	agent := &config.Agent{Name: "dog"}

	data := MCPTemplateData(cfg, "/tmp/city", agent, "dog", "/tmp/work")

	if _, present := data["EMPTY_BRIDGE_KEY"]; present {
		t.Errorf("data should not contain EMPTY_BRIDGE_KEY (empty value)")
	}
}
