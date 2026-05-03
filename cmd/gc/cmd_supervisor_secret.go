package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

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
	cmd.AddCommand(newSupervisorSecretListCmd(stdout, stderr))
	cmd.AddCommand(newSupervisorSecretReloadCmd(stdout, stderr))
	cmd.AddCommand(newSupervisorSecretImportEnvCmd(stdout, stderr))
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

// newSupervisorSecretReloadCmd returns the "secret reload" subcommand that
// sends SIGHUP to the running supervisor, triggering a live secret reload.
func newSupervisorSecretReloadCmd(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Send SIGHUP to the running supervisor to reload secrets",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			pid := supervisorAliveHook()
			if pid == 0 {
				fmt.Fprintln(stderr, "gc supervisor secret reload: supervisor not running")
				return errExit
			}
			proc, err := os.FindProcess(pid)
			if err != nil {
				return fmt.Errorf("finding supervisor process %d: %w", pid, err)
			}
			if err := proc.Signal(syscall.SIGHUP); err != nil {
				return fmt.Errorf("sending SIGHUP to PID %d: %w", pid, err)
			}
			fmt.Fprintf(stdout, "SIGHUP sent to supervisor (PID %d)\n", pid)
			return nil
		},
	}
}

// newSupervisorSecretImportEnvCmd returns the "secret import-env" subcommand
// that reads each key listed in $GC_SUPERVISOR_ENV from the current shell
// environment, writes it to the configured backend, and prints a suggested
// prefixes block for supervisor.toml.
func newSupervisorSecretImportEnvCmd(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "import-env",
		Short: "Migrate from GC_SUPERVISOR_ENV plaintext-in-plist to the secrets backend",
		Long: `Reads each key listed in $GC_SUPERVISOR_ENV from the current shell
environment, writes it to the configured backend, and prints a
suggested [secrets.keychain] (or [secrets.file]) prefixes block to
add to ~/.gc/supervisor.toml.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return err
			}
			ring, err := openSecretRing(cfg)
			if err != nil {
				return err
			}
			raw := os.Getenv("GC_SUPERVISOR_ENV")
			keys := supervisorServiceExplicitEnvKeys(raw)
			if len(keys) == 0 {
				fmt.Fprintln(stderr, "GC_SUPERVISOR_ENV is empty or unset; nothing to import")
				return nil
			}
			var imported []string
			for _, k := range keys {
				v := os.Getenv(k)
				if v == "" {
					fmt.Fprintf(stderr, "skipping %s: empty in current env\n", k)
					continue
				}
				if err := ring.Set(keyring.Item{Key: k, Data: []byte(v)}); err != nil {
					fmt.Fprintf(stderr, "set %s: %v\n", k, err)
					continue
				}
				imported = append(imported, k)
			}
			sort.Strings(imported)
			fmt.Fprintf(stdout, "Imported %d secrets to backend %q.\n\n", len(imported), backendOrAuto(cfg.Secrets.Backend))
			fmt.Fprintln(stdout, "Add the following to ~/.gc/supervisor.toml:")
			sectionName := "[secrets.keychain]"
			if cfg.Secrets.Backend == "file" {
				sectionName = "[secrets.file]"
			}
			fmt.Fprintf(stdout, "\n%s\nprefixes = [%s]\n", sectionName, quotedList(imported))
			return nil
		},
	}
}

// backendOrAuto returns b if non-empty, otherwise "auto".
func backendOrAuto(b string) string {
	if b == "" {
		return "auto"
	}
	return b
}

// quotedList formats items as a comma-separated list of Go-quoted strings
// suitable for use in a TOML array literal.
func quotedList(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(parts, ", ")
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

// secretRow holds one row of "gc supervisor secret list" output. The
// LiveStatus field is "(supervisor down)" until Task 14 wires up the
// live supervisor query via /v1/supervisor/secrets/status.
type secretRow struct {
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
	InKeyring  bool   `json:"in_keyring"`
	LiveStatus string `json:"live_status"`
	Status     string `json:"status"`
}

// newSupervisorSecretListCmd returns the "secret list" subcommand that
// reconciles configured prefixes against keyring contents, reporting
// OK, MISSING, and ORPHAN rows. Live supervisor status (STALE, MISMATCH)
// is added in Task 14 once the /v1/supervisor/secrets/status endpoint exists.
func newSupervisorSecretListCmd(stdout, stderr io.Writer) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configured secrets, keyring contents, and live supervisor state",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return err
			}
			rows, err := buildSecretRows(cfg)
			if err != nil {
				return err
			}
			if asJSON {
				return printSecretRowsJSON(stdout, rows)
			}
			return printSecretRowsTable(stdout, rows)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON instead of table")
	return cmd
}

// buildSecretRows reconciles configured prefixes against keyring contents.
// Rows are sorted by name. Status values: OK (in keyring and configured),
// MISSING (configured but absent from keyring), ORPHAN (in keyring but
// not matched by any configured prefix).
func buildSecretRows(cfg supervisor.Config) ([]secretRow, error) {
	ring, err := openSecretRing(cfg)
	if err != nil {
		return nil, err
	}
	keys, err := ring.Keys()
	if err != nil {
		return nil, err
	}

	prefixes := append([]string{}, cfg.Secrets.Keychain.Prefixes...)
	if cfg.Secrets.Backend == "file" {
		prefixes = cfg.Secrets.File.Prefixes
	}

	matched := make(map[string]bool, len(keys))
	var rows []secretRow
	for _, prefix := range prefixes {
		prefixMatched := false
		for _, k := range keys {
			if strings.HasPrefix(k, prefix) {
				matched[k] = true
				prefixMatched = true
				rows = append(rows, secretRow{
					Name:       k,
					Configured: true,
					InKeyring:  true,
					LiveStatus: "(supervisor down)",
					Status:     "OK",
				})
			}
		}
		if !prefixMatched {
			rows = append(rows, secretRow{
				Name:       prefix,
				Configured: true,
				InKeyring:  false,
				LiveStatus: "no",
				Status:     "MISSING",
			})
		}
	}
	// Orphans: in keyring but not matched by any configured prefix.
	for _, k := range keys {
		if !matched[k] {
			rows = append(rows, secretRow{
				Name:       k,
				Configured: false,
				InKeyring:  true,
				LiveStatus: "no",
				Status:     "ORPHAN",
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

// printSecretRowsTable writes rows as a fixed-width table to out.
func printSecretRowsTable(out io.Writer, rows []secretRow) error {
	fmt.Fprintf(out, "%-24s %-11s %-12s %-22s %s\n", "NAME", "CONFIGURED", "IN-KEYRING", "LIVE-IN-SUPERVISOR", "STATUS")
	for _, r := range rows {
		fmt.Fprintf(out, "%-24s %-11s %-12s %-22s %s\n",
			r.Name, yesno(r.Configured), yesno(r.InKeyring), r.LiveStatus, r.Status)
	}
	return nil
}

// yesno returns "yes" if b is true, "no" otherwise.
func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// printSecretRowsJSON writes rows as indented JSON to out.
func printSecretRowsJSON(out io.Writer, rows []secretRow) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}
