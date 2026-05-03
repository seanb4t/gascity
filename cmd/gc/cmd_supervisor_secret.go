package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/99designs/keyring"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/gastownhall/gascity/internal/supervisor"
	"github.com/gastownhall/gascity/internal/supervisor/secrets"
)

// secretPromptFn is the keyring password prompt used by the secret
// subcommands. Tests override this to avoid interactive prompts.
var secretPromptFn = keyring.TerminalPrompt

// newSupervisorSecretCmd returns the "secret" subcommand tree for
// managing secrets stored in the configured backend.
func newSupervisorSecretCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage supervisor secrets stored in the configured backend",
		Long:  `Manage secrets that the supervisor loads at startup. See engdocs/design/supervisor-secrets-v0.md.`,
	}
	cmd.AddCommand(newSupervisorSecretSetCmd(stdout, stderr))
	cmd.AddCommand(newSupervisorSecretGetCmd(stdout, stderr))
	cmd.AddCommand(newSupervisorSecretDeleteCmd(stdout, stderr))
	// list/reload/import-env subcommands added in Tasks 10/11/12
	return cmd
}

// newSupervisorSecretSetCmd returns the "secret set" subcommand that
// stores a named secret in the configured backend. The value is read
// from a no-echo terminal prompt by default, or from stdin when
// --from-stdin is set.
func newSupervisorSecretSetCmd(stdout, stderr io.Writer) *cobra.Command {
	var fromStdin bool
	cmd := &cobra.Command{
		Use:   "set <NAME>",
		Short: "Store a secret in the configured backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return err
			}
			ring, err := openSecretRing(cfg)
			if err != nil {
				return err
			}
			value, err := readSecretValue(c.InOrStdin(), fromStdin)
			if err != nil {
				return err
			}
			return ring.Set(keyring.Item{Key: name, Data: []byte(value)})
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "from-stdin", false, "read value from stdin instead of prompting")
	return cmd
}

// newSupervisorSecretGetCmd returns the "secret get" subcommand that
// prints a secret's value to stdout. Exits non-zero if the name is
// not found; stdout remains empty on failure.
func newSupervisorSecretGetCmd(stdout, stderr io.Writer) *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{
		Use:   "get <NAME>",
		Short: "Print a secret's value to stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return err
			}
			ring, err := openSecretRing(cfg)
			if err != nil {
				return err
			}
			item, err := ring.Get(args[0])
			if err != nil {
				if !quiet {
					fmt.Fprintf(stderr, "secret %q: %v\n", args[0], err)
				}
				return errExit
			}
			fmt.Fprint(stdout, string(item.Data))
			return nil
		},
	}
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress not-found message on stderr")
	return cmd
}

// newSupervisorSecretDeleteCmd returns the "secret delete" subcommand
// that removes a named secret from the configured backend. The
// operation is idempotent: deleting a name that does not exist
// succeeds silently. Requires --force or interactive confirmation.
func newSupervisorSecretDeleteCmd(stdout, stderr io.Writer) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <NAME>",
		Short: "Remove a secret from the configured backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return err
			}
			ring, err := openSecretRing(cfg)
			if err != nil {
				return err
			}
			if !force {
				if !confirm(c.InOrStdin(), stdout, fmt.Sprintf("Delete secret %q? (y/N): ", args[0])) {
					return nil
				}
			}
			if err := ring.Remove(args[0]); err != nil && !isNotFoundErr(err) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation prompt")
	return cmd
}

// loadSupervisorConfigForSecrets reads the supervisor config file
// (honoring $GC_HOME) and validates its secrets section.
func loadSupervisorConfigForSecrets() (supervisor.Config, error) {
	cfg, err := supervisor.LoadConfig(supervisor.ConfigPath())
	if err != nil {
		return cfg, fmt.Errorf("loading supervisor config: %w", err)
	}
	if err := cfg.Secrets.Validate(isReservedSupervisorEnvKey); err != nil {
		return cfg, fmt.Errorf("supervisor.toml secrets section: %w", err)
	}
	return cfg, nil
}

// openSecretRing opens the keyring described by cfg.Secrets using
// the same wrapper the supervisor uses at startup.
func openSecretRing(cfg supervisor.Config) (keyring.Keyring, error) {
	return secrets.OpenKeyring(cfg.Secrets, secretPromptFn)
}

// readSecretValue reads the secret value either from stdin (when
// fromStdin is true, trimming a trailing newline) or via a no-echo
// terminal prompt.
func readSecretValue(stdin io.Reader, fromStdin bool) (string, error) {
	if fromStdin {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\n"), nil
	}
	fmt.Fprint(os.Stderr, "Value: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// confirm prints prompt to stdout, reads a line from stdin, and
// returns true if the user typed "y" (case-insensitive).
func confirm(stdin io.Reader, stdout io.Writer, prompt string) bool {
	fmt.Fprint(stdout, prompt)
	var resp string
	fmt.Fscanln(stdin, &resp)
	return strings.EqualFold(strings.TrimSpace(resp), "y")
}

// isNotFoundErr reports whether err indicates the keyring item was not
// found. The 99designs/keyring library uses ErrKeyNotFound for Get, but
// the file backend's Remove delegates to os.Remove, which returns an OS
// path error. Both cases are treated as "already gone."
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return true
	}
	return os.IsNotExist(err)
}
