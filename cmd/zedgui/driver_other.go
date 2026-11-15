//go:build !darwin

package main

import (
	"errors"
	"os"
	"time"

	ax "github.com/go-macos/accessibility"
)

// Session is not available off macOS.
type Session struct{ base string }

// Snap is not available off macOS.
func (s *Session) Snap() (*ax.Node, error) { return nil, errUnsupported }

// Entry is one path of the archive as the list shows it.
type Entry struct {
	Path string
	Row  Row
}

var errUnsupported = errors.New("zedgui drives ZEDFREE.app and runs on macOS only")

func requireTrust() error { return errUnsupported }

func Launch(string, time.Duration) (*Session, error) { return nil, errUnsupported }

func (s *Session) Dump(*os.File) error { return errUnsupported }

func (s *Session) Wait(func(Observation) bool, time.Duration) (Observation, error) {
	return Observation{}, errUnsupported
}

func (s *Session) EnterPassword(string) error { return errUnsupported }

func (s *Session) PressButton(string) error { return errUnsupported }

func (s *Session) Walk() ([]Entry, error) { return nil, errUnsupported }

func (s *Session) Quit() {}
