package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-authn/secretsource"
)

// secretRef returns the reference to resolve: secret, or "file:"+passfile for
// the deprecated --passfile alias. Exactly one of them must be set.
func secretRef(secret, passfile string) (string, error) {
	switch {
	case secret != "" && passfile != "":
		return "", errors.New("--secret and --passfile are mutually exclusive (--passfile is deprecated)")
	case secret != "":
		return secret, nil
	case passfile != "":
		return "file:" + passfile, nil
	}
	return "", errors.New("a passphrase source is required: --secret <ref> (systemd-creds:, keychain:, keepassxc:, file:)")
}

// resolveSecret opens the reference with go-authn/secretsource, which refuses a
// file that is not a regular owner-only file and a secret over MaxSize, and
// returns a private copy of the bytes (the caller wipes it with clear). A
// file: reference whose last component is a symlink is refused here too:
// secretsource checks the target's mode, not the link. The deprecation notice
// for --passfile names no secret.
func resolveSecret(ctx context.Context, secret, passfile string, warn io.Writer) ([]byte, error) {
	ref, err := secretRef(secret, passfile)
	if err != nil {
		return nil, err
	}
	if passfile != "" && warn != nil {
		fmt.Fprintln(warn, "warning: --passfile is deprecated, use --secret file:"+passfile)
	}
	if path, ok := strings.CutPrefix(ref, "file:"); ok {
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symlink: refused", path)
		}
	}
	s, err := secretsource.Open(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return append([]byte(nil), s.Bytes()...), nil
}
