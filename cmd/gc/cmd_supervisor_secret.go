package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/gastownhall/gascity/internal/supervisor"
	"github.com/gastownhall/gascity/internal/supervisor/secrets"
)

// printAndExit is the secret-subcommand error convention: print err to
// stderr with a "gc supervisor secret:" prefix and return errExit so
// cobra (with SilenceErrors=true at the root) exits non-zero without
// the error being silently swallowed. Pre-existing errExit returns
// (commands that already printed their own message) pass through
// unchanged.
func printAndExit(stderr io.Writer, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errExit) {
		return err // already printed at the call site
	}
	fmt.Fprintf(stderr, "gc supervisor secret: %v\n", err)
	return errExit
}

// newSupervisorSecretCmd returns the "secret" subcommand tree for
// managing secrets stored in the age-encrypted store.
func newSupervisorSecretCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage supervisor secrets stored in the age-encrypted store",
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
// stores a named secret in the age store. The value is read from a
// no-echo terminal prompt by default, or from stdin when --from-stdin
// is set. When a key already exists the user is prompted to confirm
// the overwrite unless --force or --from-stdin is given.
func newSupervisorSecretSetCmd(stdout, stderr io.Writer) *cobra.Command {
	var fromStdin, force bool
	cmd := &cobra.Command{
		Use:   "set <NAME>",
		Short: "Store a secret in the configured backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return printAndExit(stderr, err)
			}
			store, err := openSecretStore(cfg)
			if err != nil {
				return printAndExit(stderr, err)
			}
			// Overwrite confirmation. --from-stdin always proceeds because the
			// caller is non-interactive.
			if !force && !fromStdin {
				if _, err := store.Get(name); !isNotFoundErr(err) {
					if !confirm(c.InOrStdin(), stdout, fmt.Sprintf("Secret %q already exists. Overwrite? (y/N): ", name)) {
						return nil
					}
				}
			}
			value, err := readSecretValue(c.InOrStdin(), fromStdin)
			if err != nil {
				return printAndExit(stderr, err)
			}
			return store.Set(name, []byte(value))
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "from-stdin", false, "read value from stdin instead of prompting")
	cmd.Flags().BoolVar(&force, "force", false, "skip overwrite confirmation")
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
				return printAndExit(stderr, err)
			}
			store, err := openSecretStore(cfg)
			if err != nil {
				return printAndExit(stderr, err)
			}
			data, err := store.Get(args[0])
			if err != nil {
				if !quiet {
					fmt.Fprintf(stderr, "secret %q: %v\n", args[0], err)
				}
				return errExit
			}
			fmt.Fprint(stdout, string(data))
			return nil
		},
	}
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress not-found message on stderr")
	return cmd
}

// newSupervisorSecretDeleteCmd returns the "secret delete" subcommand
// that removes a named secret from the age store. The operation is
// idempotent: deleting a name that does not exist succeeds silently.
// Requires --force or interactive confirmation.
func newSupervisorSecretDeleteCmd(stdout, stderr io.Writer) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <NAME>",
		Short: "Remove a secret from the age-encrypted store",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return printAndExit(stderr, err)
			}
			store, err := openSecretStore(cfg)
			if err != nil {
				return printAndExit(stderr, err)
			}
			if !force {
				if !confirm(c.InOrStdin(), stdout, fmt.Sprintf("Delete secret %q? (y/N): ", args[0])) {
					return nil
				}
			}
			if err := store.Remove(args[0]); err != nil && !isNotFoundErr(err) {
				return printAndExit(stderr, err)
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
// environment, writes it to the age store, and prints a suggested
// [secrets.age] keys = [...] block for supervisor.toml.
func newSupervisorSecretImportEnvCmd(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "import-env",
		Short: "Migrate from GC_SUPERVISOR_ENV plaintext-in-plist to the age store",
		Long: `Reads each key listed in $GC_SUPERVISOR_ENV from the current shell
environment, writes it to the age-encrypted store, and prints a
suggested [secrets.age] keys = [...] block to add to ~/.gc/supervisor.toml.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return printAndExit(stderr, err)
			}
			store, err := openSecretStore(cfg)
			if err != nil {
				return printAndExit(stderr, err)
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
				if err := store.Set(k, []byte(v)); err != nil {
					fmt.Fprintf(stderr, "set %s: %v\n", k, err)
					continue
				}
				imported = append(imported, k)
			}
			sort.Strings(imported)
			fmt.Fprintf(stdout, "Imported %d secrets to the age store.\n\n", len(imported))
			fmt.Fprintln(stdout, "Add the following to ~/.gc/supervisor.toml:")
			fmt.Fprintf(stdout, "\n[secrets.age]\nkeys = [%s]\n", quotedList(imported))
			return nil
		},
	}
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

// openSecretStore opens the age-encrypted store described by
// cfg.Secrets.Age. Same constructor the supervisor uses at startup.
func openSecretStore(cfg supervisor.Config) (*secrets.Store, error) {
	return secrets.Open(cfg.Secrets.Age)
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

// isNotFoundErr reports whether err indicates the secret was not
// found in the age store.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, secrets.ErrNotFound)
}

// secretRow holds one row of "gc supervisor secret list" output.
type secretRow struct {
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
	InKeyring  bool   `json:"in_keyring"`
	LiveStatus string `json:"live_status"`
	Status     string `json:"status"`
}

// newSupervisorSecretListCmd returns the "secret list" subcommand that
// reconciles configured keys against the age store contents, reporting
// OK, MISSING, ORPHAN, STALE, and MISMATCH rows.
func newSupervisorSecretListCmd(stdout, stderr io.Writer) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configured secrets, age store contents, and live supervisor state",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return printAndExit(stderr, err)
			}
			rows, err := buildSecretRows(cfg)
			if err != nil {
				return printAndExit(stderr, err)
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

// buildSecretRows reconciles the configured key list against age store
// contents, then enriches each row with live supervisor state from the
// /v1/supervisor/secrets/status endpoint. Rows are sorted by name.
// Status values: OK (configured + in store + supervisor agrees),
// MISMATCH (configured + in store + supervisor hash differs),
// STALE (configured + in store + supervisor does not report it),
// MISSING (configured but absent from store),
// ORPHAN (in store but not in the configured key list).
// When the supervisor is unreachable, LiveStatus is "(supervisor down)"
// and configured+in-store secrets retain "OK" status.
func buildSecretRows(cfg supervisor.Config) ([]secretRow, error) {
	store, err := openSecretStore(cfg)
	if err != nil {
		return nil, err
	}
	storedKeys, err := store.Keys()
	if err != nil {
		return nil, err
	}
	inStore := make(map[string]bool, len(storedKeys))
	for _, k := range storedKeys {
		inStore[k] = true
	}

	liveByName, liveErr := fetchLiveSupervisorSecrets(cfg.Supervisor.PortOrDefault())

	configured := make(map[string]bool, len(cfg.Secrets.Age.Keys))
	var rows []secretRow
	for _, key := range cfg.Secrets.Age.Keys {
		configured[key] = true
		if !inStore[key] {
			rows = append(rows, secretRow{
				Name:       key,
				Configured: true,
				InKeyring:  false,
				LiveStatus: "no",
				Status:     "MISSING",
			})
			continue
		}
		liveStatus := "(supervisor down)"
		status := "OK"
		if liveErr == nil {
			if live, ok := liveByName[key]; ok {
				liveStatus = "yes"
				data, _ := store.Get(key)
				localSum := sha256.Sum256(data)
				localHash := hex.EncodeToString(localSum[:])
				if live.SHA256 != localHash {
					status = "MISMATCH"
				}
			} else {
				liveStatus = "no"
				status = "STALE"
			}
		}
		rows = append(rows, secretRow{
			Name:       key,
			Configured: true,
			InKeyring:  true,
			LiveStatus: liveStatus,
			Status:     status,
		})
	}
	// Orphans: in the store but not in the configured key list.
	for _, k := range storedKeys {
		if configured[k] {
			continue
		}
		rows = append(rows, secretRow{
			Name:       k,
			Configured: false,
			InKeyring:  true,
			LiveStatus: "no",
			Status:     "ORPHAN",
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

// liveSecret is the per-secret payload returned by
// GET /v1/supervisor/secrets/status.
type liveSecret struct {
	Name   string `json:"name"`
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
}

// fetchLiveSupervisorSecrets queries the running supervisor's
// /v1/supervisor/secrets/status endpoint and returns a map of secret name
// to liveSecret. The base URL is taken from GC_SUPERVISOR_API_URL when
// set (used in tests), falling back to the configured port. Any network
// or decode error is returned as-is; callers treat a non-nil error as
// "supervisor down" and fall back to placeholder status.
func fetchLiveSupervisorSecrets(port int) (map[string]liveSecret, error) {
	base := os.Getenv("GC_SUPERVISOR_API_URL")
	if base == "" {
		base = fmt.Sprintf("http://127.0.0.1:%d", port)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(base + "/v1/supervisor/secrets/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Secrets []liveSecret `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	out := make(map[string]liveSecret, len(body.Secrets))
	for _, s := range body.Secrets {
		out[s.Name] = s
	}
	return out, nil
}

// printSecretRowsTable writes rows as a fixed-width table to out.
func printSecretRowsTable(out io.Writer, rows []secretRow) error {
	fmt.Fprintf(out, "%-24s %-11s %-12s %-22s %s\n", "NAME", "CONFIGURED", "IN-STORE", "LIVE-IN-SUPERVISOR", "STATUS")
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
