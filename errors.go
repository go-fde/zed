package zed

import "errors"

var (
	// ErrFormat reports data that does not follow the .zed layout.
	ErrFormat = errors.New("zed: invalid archive")
	// ErrPassword reports that no password user accepts the password.
	ErrPassword = errors.New("zed: wrong password")
	// ErrUnsupported reports a feature this package does not implement (RSA
	// users, unknown hash functions or encryption modes).
	ErrUnsupported = errors.New("zed: unsupported")
	// ErrLimit reports a size, count or iteration number above a Limits field,
	// refused before the work is done.
	ErrLimit = errors.New("zed: limit exceeded")
)
