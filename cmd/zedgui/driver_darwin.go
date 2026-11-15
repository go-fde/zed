package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	ax "github.com/go-macos/accessibility"
)

const (
	appName = "ZEDFREE"
	appExe  = "/Applications/ZEDFREE.app/Contents/MacOS/zed"
)

// Session is one ZEDFREE process started by this tool.
type Session struct {
	pid     int
	root    *ax.Element
	base    string
	timeout time.Duration
}

func findPID() int {
	// Not ax.Applications: NSWorkspace's list is a cache that lags in both
	// directions (a killed process stays, a started one is missing). The
	// process table is the authority; the full executable path tells ZEDFREE
	// from the Zed editor, whose executable is also called "zed".
	out, err := exec.Command("pgrep", "-f", "^"+regexp.QuoteMeta(appExe)+"$").Output()
	if err != nil {
		return 0
	}
	for _, f := range strings.Fields(string(out)) {
		if pid, err := strconv.Atoi(f); err == nil && pid != os.Getpid() {
			return pid
		}
	}
	return 0
}

// requireTrust stops, with the exact thing to authorise, if this process may
// not use the Accessibility API. It never prompts and never works around TCC.
func requireTrust() error {
	st, err := ax.Status()
	if err != nil {
		return err
	}
	if !st.Trusted {
		return fmt.Errorf("not trusted for Accessibility; authorise it in System Settings > Privacy & Security > Accessibility: %s", st.Advice())
	}
	return nil
}

// Launch opens the archive in ZEDFREE. It refuses if ZEDFREE already runs: the
// session must own the process it will quit.
func Launch(archive string, timeout time.Duration) (*Session, error) {
	// A process this tool just quit can linger in the application list for a
	// few seconds; give it that long before taking it for someone's own.
	for i := 0; i < 40 && findPID() != 0; i++ {
		time.Sleep(250 * time.Millisecond)
	}
	if findPID() != 0 {
		return nil, errors.New("ZEDFREE is already running; quit it first (this tool only quits what it started)")
	}
	if _, err := os.Stat(archive); err != nil {
		return nil, err
	}
	if err := exec.Command("open", "-a", appName, archive).Run(); err != nil {
		return nil, fmt.Errorf("open -a %s: %w", appName, err)
	}
	s := &Session{base: filepath.Base(archive), timeout: timeout}
	deadline := time.Now().Add(timeout)
	for s.pid == 0 && time.Now().Before(deadline) {
		s.pid = findPID()
		time.Sleep(200 * time.Millisecond)
	}
	if s.pid == 0 {
		return nil, errors.New("ZEDFREE did not start")
	}
	root, err := ax.ApplicationElement(s.pid)
	if err != nil {
		s.Quit()
		return nil, err
	}
	s.root = root
	return s, nil
}

// Snap copies the application's tree. Every editable value is withheld.
func (s *Session) Snap() (*ax.Node, error) {
	return s.root.Snapshot(ax.SnapshotLimits{MaxDepth: 14, RedactEditable: true})
}

// Dump writes the redacted tree.
func (s *Session) Dump(w *os.File) error {
	n, err := s.Snap()
	if err != nil {
		return err
	}
	return n.Render(w)
}

// Wait polls until pred holds for the observation, or the timeout.
func (s *Session) Wait(pred func(Observation) bool, timeout time.Duration) (Observation, error) {
	deadline := time.Now().Add(timeout)
	var obs Observation
	for {
		n, err := s.Snap()
		if err == nil {
			obs = Classify(n, s.base)
			if pred(obs) {
				return obs, nil
			}
		}
		if time.Now().After(deadline) {
			return obs, errors.New("timed out")
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// EnterPassword types the password into the password field and presses OK.
func (s *Session) EnterPassword(pw string) error {
	groups, err := s.root.Locate(func(n *ax.Node) bool {
		for _, c := range n.Children {
			if c.Role == "AXStaticText" && strings.Contains(strings.ToLower(c.Value), "password:") {
				return true
			}
		}
		return false
	}, ax.SnapshotLimits{MaxDepth: 14, RedactEditable: true})
	if err != nil || len(groups) == 0 {
		return errors.New("no password field found")
	}
	defer ax.CloseElements(groups)
	kids, err := groups[0].Children()
	if err != nil {
		return err
	}
	defer ax.CloseElements(kids)
	var field *ax.Element
	for _, k := range kids {
		if k.Role() == "AXTextField" {
			field = k
		}
	}
	if field == nil {
		return errors.New("no password field found")
	}
	if err := field.SetValue(pw); err != nil {
		// Some secure fields refuse AXValue: go through the keyboard.
		if ferr := field.Focus(); ferr != nil {
			return fmt.Errorf("neither AXValue nor focus accepted: %v", err)
		}
		if terr := ax.TypeText(s.pid, pw, 15*time.Millisecond); terr != nil {
			return terr
		}
	}
	return s.PressButton("OK")
}

// PressButton presses the button with this title.
func (s *Session) PressButton(title string) error {
	bs, err := s.root.Locate(func(n *ax.Node) bool { return n.Role == "AXButton" && n.Title == title }, ax.SnapshotLimits{MaxDepth: 14, RedactEditable: true})
	if err != nil || len(bs) == 0 {
		return fmt.Errorf("no %q button", title)
	}
	defer ax.CloseElements(bs)
	return bs[0].Press()
}

// topIsOurs reports whether the topmost ordinary window at p is ZEDFREE's.
func (s *Session) topIsOurs(p ax.Point) bool {
	ws, err := ax.ServerWindows()
	if err != nil {
		return false
	}
	for _, w := range ws {
		if w.Layer == 0 && w.Frame.Contains(p) {
			return w.PID == s.pid
		}
	}
	return false
}

// DoubleClick double-clicks an element's centre. The click is posted to the
// screen, so it is refused unless ZEDFREE's window is on top at that point:
// another application's window is never clicked.
func (s *Session) DoubleClick(el *ax.Element) error { return s.click(el, 2) }

func (s *Session) click(el *ax.Element, count int) error {
	f, err := el.Frame()
	if err != nil {
		return err
	}
	for i := 0; i < 5 && !s.topIsOurs(f.Center()); i++ {
		_ = exec.Command("open", "-a", appName).Run()
		time.Sleep(600 * time.Millisecond)
	}
	if !s.topIsOurs(f.Center()) {
		return errors.New("ZEDFREE is not the top window at the click point; not clicking")
	}
	return ax.ClickAt(0, f.Center(), count)
}

func (s *Session) listElement() (*ax.Element, error) {
	gs, err := s.root.Locate(func(n *ax.Node) bool {
		for _, c := range n.Children {
			if c.Role == "AXColumn" && c.Title == "Name" {
				return true
			}
		}
		return false
	}, ax.SnapshotLimits{MaxDepth: 14, RedactEditable: true})
	if err != nil || len(gs) == 0 {
		return nil, errors.New("no file list")
	}
	for _, g := range gs[1:] {
		_ = g.Close()
	}
	return gs[0], nil
}

func (s *Session) rows() ([]Row, error) {
	n, err := s.Snap()
	if err != nil {
		return nil, err
	}
	m := MainWindow(n)
	if m == nil {
		return nil, errors.New("no main window")
	}
	return Rows(m), nil
}

// up goes to the parent folder: ZEDFREE's list answers Backspace like a file
// browser does (found by experiment: the breadcrumb entry ignores both AXPress
// and a click).
func (s *Session) up(prev []Row) []Row {
	_ = ax.PressKey(s.pid, 51)
	return s.waitRowsChange(prev)
}

func (s *Session) waitRowsChange(prev []Row) []Row {
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if cur, err := s.rows(); err == nil && !reflect.DeepEqual(cur, prev) {
			time.Sleep(300 * time.Millisecond)
			cur, _ = s.rows()
			return cur
		}
	}
	return prev
}

// enter descends into the folder called name of the current view.
func (s *Session) enter(name string, prev []Row) ([]Row, error) {
	lst, err := s.listElement()
	if err != nil {
		return nil, err
	}
	defer lst.Close()
	kids, err := lst.Children()
	if err != nil {
		return nil, err
	}
	defer ax.CloseElements(kids)
	for _, k := range kids {
		if k.Role() == "AXGroup" && k.Title() == name {
			if err := s.DoubleClick(k); err != nil {
				return nil, err
			}
			return s.waitRowsChange(prev), nil
		}
	}
	if os.Getenv("ZED_GUI_DUMP") == "1" {
		_ = s.Dump(os.Stderr)
	}
	return nil, fmt.Errorf("no entry %q in the list", name)
}

// Entry is one path of the archive as the list shows it.
type Entry struct {
	Path string
	Row  Row
}

// Walk lists the whole archive through the GUI, folders first-class.
func (s *Session) Walk() ([]Entry, error) {
	var out []Entry
	var rec func(dir string, cur []Row) error
	rec = func(dir string, cur []Row) error {
		for _, r := range cur {
			out = append(out, Entry{dir + r.Name, r})
		}
		for _, r := range cur {
			if !r.IsFolder() {
				continue
			}
			child, err := s.enter(r.Name, cur)
			if err != nil {
				return err
			}
			if err := rec(dir+r.Name+"/", child); err != nil {
				return err
			}
			if back := s.up(child); !reflect.DeepEqual(back, cur) {
				return fmt.Errorf("going up from %s%s did not return to the parent list", dir, r.Name)
			}
		}
		return nil
	}
	cur, err := s.rows()
	if err != nil {
		return nil, err
	}
	return out, rec("", cur)
}

// Quit ends the process this session started, politely first.
func (s *Session) Quit() {
	if s.root != nil {
		_ = s.root.Close()
	}
	if s.pid == 0 {
		return
	}
	// LaunchServices keeps answering for the process for a moment after it is
	// gone, and an `open` in that moment goes to nobody: let it forget.
	defer time.Sleep(3 * time.Second)
	_ = syscall.Kill(s.pid, syscall.SIGTERM)
	for i := 0; i < 25; i++ {
		if findPID() != s.pid {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = syscall.Kill(s.pid, syscall.SIGKILL)
	for i := 0; i < 25 && findPID() == s.pid; i++ {
		time.Sleep(200 * time.Millisecond)
	}
}
