// Command zedgui opens a ZED! archive in ZEDFREE.app, enters the password and
// reports what ZEDFREE shows: the file and folder list, or the error message.
// It drives the real application through the macOS Accessibility API, so no
// human has to click.
//
// It is a live tool: every command needs ZED_GUI=1 in the environment, and the
// terminal (or the binary) must be authorised in System Settings > Privacy &
// Security > Accessibility. The password is resolved by this program from a
// go-authn/secretsource reference (--secret: keychain:, systemd-creds:,
// keepassxc:, or an owner-only file:), has no default, and is never printed,
// logged or part of a dump: every editable field's value is withheld.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var osExit = os.Exit

var extra []*cobra.Command

// RootCmd builds the command tree.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "zedgui",
		Short:         "Drive ZEDFREE.app through Accessibility to test ZED! archives",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if os.Getenv("ZED_GUI") != "1" {
				return errors.New("set ZED_GUI=1 to run the live GUI driver")
			}
			return requireTrust()
		},
	}
	var secret, pwFile string
	var cont, empty bool
	var wrong bool
	var timeout time.Duration
	var expect []string

	check := &cobra.Command{
		Use:   "check ARCHIVE",
		Short: "Open each ARCHIVE in turn, enter the password, print the verdict and the list",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if empty {
				expect = []string{}
			}
			// Resolved before the GUI is touched: a refused source launches nothing.
			pw, err := resolveSecret(cmd.Context(), secret, pwFile, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			defer clear(pw)
			failed := false
			for _, a := range args {
				v, err := runCheck(cmd.OutOrStdout(), a, string(pw), wrong, cont, timeout, expect)
				if err != nil {
					return err
				}
				failed = failed || !v
				fmt.Fprintln(cmd.OutOrStdout())
			}
			if failed {
				osExit(1)
			}
			return nil
		},
	}
	check.Flags().StringVar(&secret, "secret", "", "reference of the password (no default): keychain:SERVICE/ACCOUNT, systemd-creds:NAME, keepassxc:..., or file:PATH (owner-only, not a symlink, at most 4096 bytes)")
	check.Flags().StringVar(&pwFile, "password-file", "", "deprecated: same as --secret file:PATH (the whole file is the password, one trailing newline stripped)")
	check.Flags().MarkDeprecated("password-file", "use --secret file:PATH")
	check.MarkFlagsOneRequired("secret", "password-file")
	check.MarkFlagsMutuallyExclusive("secret", "password-file")
	check.Flags().BoolVar(&empty, "expect-empty", false, "expect an empty archive")
	check.Flags().BoolVar(&cont, "continue", false, "answer Yes to a Yes/No warning (e.g. a corrupted-container warning) and report what follows")
	check.Flags().BoolVar(&wrong, "wrong-password", false, "negative control: enter a wrong password and expect a refusal")
	check.Flags().DurationVar(&timeout, "timeout", 40*time.Second, "how long to wait for each state")
	check.Flags().StringArrayVar(&expect, "expect", nil, "expected path (repeatable; empty archive: none); the listing is compared with them")

	dump := &cobra.Command{
		Use:   "dump ARCHIVE",
		Short: "Open ARCHIVE and print the redacted accessibility tree of the password dialog",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := Launch(args[0], timeout)
			if err != nil {
				return err
			}
			defer s.Quit()
			if _, err := s.Wait(func(o Observation) bool { return o.Kind != KindNone }, timeout); err != nil {
				return err
			}
			return s.Dump(os.Stdout)
		},
	}
	dump.Flags().DurationVar(&timeout, "timeout", 40*time.Second, "how long to wait")
	root.AddCommand(check, dump)
	root.AddCommand(extra...)
	return root
}

// runCheck returns whether the outcome is the one expected: opened (or refused
// with --wrong-password), and the listing equal to --expect when given.
func runCheck(w io.Writer, archive, pw string, wrong, cont bool, timeout time.Duration, expect []string) (bool, error) {
	if wrong {
		pw += "-wrong"
	}
	s, err := Launch(archive, timeout)
	if err != nil {
		return false, err
	}
	defer s.Quit()
	fmt.Fprintf(w, "archive: %s\n", filepath.Base(archive))
	obs, err := s.Wait(func(o Observation) bool {
		return o.Kind == KindPassword || o.Kind == KindOpened || o.Kind == KindMessage
	}, timeout)
	if err != nil {
		fmt.Fprintf(w, "verdict: TIMEOUT before any prompt (state %s %q)\n", obs.Kind, obs.Texts)
		return false, nil
	}
	if obs.Kind == KindMessage {
		fmt.Fprintf(w, "verdict: REFUSED before the password: %q\n", obs.Texts)
		return false, nil
	}
	if obs.Kind == KindPassword {
		first := obs.Texts
		if err := s.EnterPassword(pw); err != nil {
			return false, err
		}
		obs = s.settle(first, timeout)
		if obs.Kind == KindMessage && cont && strings.Contains(strings.Join(obs.Texts, "|"), "[Yes]") {
			fmt.Fprintf(w, "warning: %q\n", obs.Texts)
			if err := s.PressButton("Yes"); err != nil {
				return false, err
			}
			obs = s.settle(nil, timeout)
		}
	}
	switch obs.Kind {
	case KindOpened:
		if os.Getenv("ZED_GUI_DUMP") == "1" {
			_ = s.Dump(os.Stderr)
		}
		entries, err := s.Walk()
		if err != nil {
			fmt.Fprintf(w, "verdict: OPENED, listing failed: %v\n", err)
			return false, nil
		}
		fmt.Fprintf(w, "verdict: OPENED\n")
		var got []string
		for _, e := range entries {
			fmt.Fprintf(w, "  %s | size %q | %s\n", e.Path, e.Row.Size, e.Row.Type)
			got = append(got, e.Path)
		}
		if wrong {
			return false, nil
		}
		return compare(w, got, expect), nil
	case KindEmpty:
		fmt.Fprintf(w, "verdict: NOT OPENED: ZEDFREE is back on its empty start screen, no message\n")
		return wrong, nil
	case KindMessage, KindPassword:
		fmt.Fprintf(w, "verdict: REFUSED: %q\n", obs.Texts)
		return wrong, nil
	}
	fmt.Fprintf(w, "verdict: TIMEOUT after the password (state %s %q)\n", obs.Kind, obs.Texts)
	if os.Getenv("ZED_GUI_DUMP") == "1" {
		_ = s.Dump(os.Stderr)
	}
	return false, nil
}

// settle waits after OK until the archive is open, a message is shown, or the
// password dialog has stood unchanged for passwordGrace without the progress
// window appearing (ZEDFREE shows no text for a wrong password: it asks again).
// The progress window extends the wait, so a slow key derivation is not taken
// for a refusal.
func (s *Session) settle(first []string, timeout time.Duration) Observation {
	const passwordGrace = 8 * time.Second
	start := time.Now()
	const emptyGrace = 6 * time.Second
	last := start
	var emptySince time.Time
	var obs Observation
	for time.Since(start) < timeout {
		time.Sleep(300 * time.Millisecond)
		n, err := s.Snap()
		if err != nil {
			continue
		}
		obs = Classify(n, s.base)
		switch obs.Kind {
		case KindOpened, KindMessage:
			return obs
		case KindEmpty:
			if emptySince.IsZero() {
				emptySince = time.Now()
			}
			if time.Since(emptySince) > emptyGrace {
				return obs
			}
			continue
		case KindBusy:
			emptySince = time.Time{}
			last = time.Now()
		case KindPassword:
			if time.Since(last) > passwordGrace {
				if strings.Join(obs.Texts, "|") == strings.Join(first, "|") {
					obs.Texts = []string{"(the password dialog is shown again, no message)"}
				}
				obs.Kind = KindMessage
				return obs
			}
		default:
			last = time.Now()
		}
	}
	return obs
}

func compare(w io.Writer, got, expect []string) bool {
	if expect == nil {
		return true
	}
	g := append([]string(nil), got...)
	e := append([]string(nil), expect...)
	sort.Strings(g)
	sort.Strings(e)
	if strings.Join(g, "\n") == strings.Join(e, "\n") {
		fmt.Fprintf(w, "listing: matches the %d expected paths\n", len(e))
		return true
	}
	in := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	for _, x := range e {
		if !in(g, x) {
			fmt.Fprintf(w, "listing: MISSING %s\n", x)
		}
	}
	for _, x := range g {
		if !in(e, x) {
			fmt.Fprintf(w, "listing: EXTRA %s\n", x)
		}
	}
	return false
}

func main() {
	root := RootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "zedgui:", err)
		osExit(2)
	}
}
