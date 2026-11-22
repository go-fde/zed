//go:build !windows

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/secretsource"
)

const testPass = "a-passphrase-long-enough"

func writeMode(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecretRef(t *testing.T) {
	for _, c := range []struct {
		secret, passfile, want string
		bad                    bool
	}{
		{"file:/x", "", "file:/x", false},
		{"systemd-creds:vc", "", "systemd-creds:vc", false},
		{"", "/p", "file:/p", false},
		{"", "", "", true},
		{"file:/x", "/p", "", true},
	} {
		got, err := secretRef(c.secret, c.passfile)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("secretRef(%q,%q) = %q, %v", c.secret, c.passfile, got, err)
		}
	}
}

func TestResolveSecretFile(t *testing.T) {
	p := writeMode(t, "pw", []byte(testPass+"\n"), 0o600)
	var warn bytes.Buffer
	got, err := resolveSecret(context.Background(), "", p, &warn)
	if err != nil || string(got) != testPass {
		t.Fatalf("passfile: %q, %v", got, err)
	}
	if !strings.Contains(warn.String(), "deprecated") || strings.Contains(warn.String(), testPass) {
		t.Errorf("warning = %q", warn.String())
	}
	warn.Reset()
	got, err = resolveSecret(context.Background(), "file:"+p, "", &warn)
	if err != nil || string(got) != testPass || warn.Len() != 0 {
		t.Fatalf("secret: %q, %v, warn %q", got, err, warn.String())
	}
	// the copy is private: wiping it must not matter to a second resolution
	clear(got)
	if again, err := resolveSecret(context.Background(), "file:"+p, "", nil); err != nil || string(again) != testPass {
		t.Fatalf("again: %q, %v", again, err)
	}
}

func TestResolveSecretRefusals(t *testing.T) {
	dir := t.TempDir()
	good := writeMode(t, "good", []byte(testPass), 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	for name, ref := range map[string]string{
		"group-readable": "file:" + writeMode(t, "g", []byte(testPass), 0o640),
		"world-readable": "file:" + writeMode(t, "w", []byte(testPass), 0o644),
		"symlink":        "file:" + link,
		"oversize":       "file:" + writeMode(t, "big", bytes.Repeat([]byte("x"), secretsource.MaxSize+1), 0o600),
		"missing":        "file:" + filepath.Join(dir, "nope"),
		"unknown scheme": "carrier-pigeon:x",
	} {
		for _, viaFlag := range []bool{false, true} {
			var got []byte
			var err error
			if viaFlag {
				if !strings.HasPrefix(ref, "file:") {
					continue
				}
				got, err = resolveSecret(context.Background(), "", strings.TrimPrefix(ref, "file:"), nil)
			} else {
				got, err = resolveSecret(context.Background(), ref, "", nil)
			}
			if err == nil || len(got) != 0 {
				t.Errorf("%s (flag=%v): accepted (%d bytes)", name, viaFlag, len(got))
			}
			if err != nil && strings.Contains(err.Error(), testPass) {
				t.Errorf("%s: error mentions the secret: %v", name, err)
			}
		}
	}
}

func TestResolveSecretNoSource(t *testing.T) {
	if _, err := resolveSecret(context.Background(), "", "", nil); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatal("no source accepted, or refused for another reason:", err)
	}
	both := writeMode(t, "both", []byte(testPass), 0o600)
	if _, err := resolveSecret(context.Background(), "file:"+both, both, nil); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatal("both sources accepted, or refused for another reason:", err)
	}
}

func FuzzSecretRef(f *testing.F) {
	f.Add("file:/x", "")
	f.Add("", "/p")
	f.Add("systemd-creds:../../etc/shadow", "")
	f.Fuzz(func(t *testing.T, secret, passfile string) {
		ref, err := secretRef(secret, passfile)
		if err == nil && ref == "" {
			t.Fatal("empty reference without an error")
		}
		if err == nil && secret != "" && passfile != "" {
			t.Fatal("both sources accepted")
		}
	})
}

// There is no default password source and no plaintext document is read for
// a password: --secret and --password-file default to empty, and the
// --password-marker flag (a `quoted` token out of prose) is gone.
func TestCheckHasNoDefaultSecret(t *testing.T) {
	check, _, err := RootCmd().Find([]string{"check"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"secret", "password-file"} {
		f := check.Flags().Lookup(name)
		if f == nil || f.DefValue != "" {
			t.Errorf("--%s: %+v", name, f)
		}
	}
	if check.Flags().Lookup("password-marker") != nil {
		t.Error("--password-marker is back")
	}
	if check.Flags().Lookup("password-file").Deprecated == "" {
		t.Error("--password-file is not marked deprecated")
	}
}
