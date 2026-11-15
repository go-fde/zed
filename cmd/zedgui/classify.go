package main

import (
	"errors"
	"os"
	"strings"

	ax "github.com/go-macos/accessibility"
)

// readPassword returns the last non-empty line of the file at path. The value
// is held only by the caller; nothing here prints it.
func readPassword(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			return s, nil
		}
	}
	return "", errors.New("the password file has no non-empty line")
}

// readMarkedPassword returns the first `backquoted` token of the first line
// containing marker.
func readMarkedPassword(path, marker string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.Contains(l, marker) {
			continue
		}
		parts := strings.Split(l, "`")
		if len(parts) >= 3 && parts[1] != "" {
			return parts[1], nil
		}
		return "", errors.New("the marked line has no `quoted` password")
	}
	return "", errors.New("no line contains the marker")
}

// Kind is what the application is showing.
type Kind string

const (
	// KindNone: no window of ours is recognisable yet.
	KindNone Kind = "none"
	// KindPassword: the "enter the password" dialog.
	KindPassword Kind = "password"
	// KindBusy: the "Opening container..." progress window.
	KindBusy Kind = "busy"
	// KindMessage: a dialog with text and no password field (an error).
	KindMessage Kind = "message"
	// KindOpened: the main window shows the container's file list.
	KindOpened Kind = "opened"
)

// KindEmpty: only the start screen ("Drop a ZED! encrypted container ...").
const KindEmpty Kind = "empty"

func startScreen(w *ax.Node) bool {
	for _, t := range w.FindRole("AXStaticText", "") {
		if strings.HasPrefix(t.Value, "Drop a ZED!") {
			return true
		}
	}
	return false
}

// Observation is the classified state of the application's windows.
type Observation struct {
	Kind Kind
	// Texts are the visible texts of the dialog (Password, Message), or empty.
	Texts []string
}

func windows(app *ax.Node) []*ax.Node {
	var out []*ax.Node
	for i := range app.Children {
		if app.Children[i].Role == "AXWindow" {
			out = append(out, &app.Children[i])
		}
	}
	return out
}

func hasRole(n *ax.Node, role string) bool {
	return len(n.FindRole(role, "")) > 0
}

// listGroup returns the group holding the file list: the one with the Name
// column among its children.
func listGroup(n *ax.Node) *ax.Node {
	var found *ax.Node
	n.Walk(func(c *ax.Node, _ int) bool {
		if found == nil {
			for i := range c.Children {
				if c.Children[i].Role == "AXColumn" && c.Children[i].Title == "Name" {
					found = c
				}
			}
		}
		return found == nil
	})
	return found
}

// Classify decides what the application shows. base is the archive's file
// name, which the main window carries in its title once the archive is open.
func Classify(app *ax.Node, base string) Observation {
	obs := Observation{Kind: KindNone}
	for _, w := range windows(app) {
		switch {
		case w.Subrole == "AXStandardWindow":
			if strings.Contains(w.Title, base) && listGroup(w) != nil {
				return Observation{Kind: KindOpened}
			}
			if len(app.Children) > 0 && len(windows(app)) == 1 && startScreen(w) {
				obs.Kind = KindEmpty
			}
		case hasRole(w, "AXProgressIndicator"):
			if obs.Kind == KindNone {
				obs.Kind = KindBusy
			}
		case hasRole(w, "AXTextField") && hasRole(w, "AXButton"):
			return Observation{Kind: KindPassword, Texts: dialogTexts(w)}
		default:
			if t := dialogTexts(w); len(t) > 0 && w.Subrole != "AXStandardWindow" {
				obs = Observation{Kind: KindMessage, Texts: t}
			}
		}
	}
	return obs
}

// dialogTexts lists what a dialog says: its static texts and button titles, in
// order. Editable fields are redacted by the snapshot and never listed.
func dialogTexts(w *ax.Node) []string {
	var out []string
	w.Walk(func(c *ax.Node, _ int) bool {
		if c.Secure {
			return true
		}
		switch c.Role {
		case "AXStaticText":
			for _, s := range []string{c.Value, c.Description} {
				if s != "" {
					out = append(out, s)
				}
			}
		case "AXButton":
			if c.Title != "" && c.Subrole == "" {
				out = append(out, "["+c.Title+"]")
			}
		}
		return true
	})
	return out
}

// Row is one entry of the file list.
type Row struct {
	Name, Size, Type, Date string
}

// IsFolder reports whether the entry is a folder.
func (r Row) IsFolder() bool { return r.Type == "Folder" }

// Rows reads the file list shown in the main window. The list exposes its
// cells as titled groups after the column headers; the cells come row by row
// (name, size, type, date) or column by column, and the type cell tells which:
// it is "Folder" or "File '...'".
func Rows(main *ax.Node) []Row {
	lg := listGroup(main)
	if lg == nil {
		return nil
	}
	var cells []string
	for i := range lg.Children {
		if lg.Children[i].Role == "AXGroup" {
			cells = append(cells, lg.Children[i].Title)
		}
	}
	if len(cells) < 4 || len(cells)%4 != 0 {
		return nil
	}
	n := len(cells) / 4
	isType := func(s string) bool { return s == "Folder" || strings.HasPrefix(s, "File ") }
	var rows []Row
	if isType(cells[2]) {
		for i := 0; i < n; i++ {
			c := cells[4*i : 4*i+4]
			rows = append(rows, Row{c[0], c[1], c[2], c[3]})
		}
		return rows
	}
	for i := 0; i < n; i++ {
		rows = append(rows, Row{cells[i], cells[n+i], cells[2*n+i], cells[3*n+i]})
	}
	return rows
}

// MainWindow returns the standard window of the tree.
func MainWindow(app *ax.Node) *ax.Node {
	for _, w := range windows(app) {
		if w.Subrole == "AXStandardWindow" {
			return w
		}
	}
	return nil
}
