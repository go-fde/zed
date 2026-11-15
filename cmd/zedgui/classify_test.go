package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ax "github.com/go-macos/accessibility"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.md")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadPasswordLastNonEmptyLine(t *testing.T) {
	p := writeFile(t, "intro\r\nsecret-value  \r\n\r\n\n")
	got, err := readPassword(p)
	if err != nil || got != "secret-value" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := readPassword(writeFile(t, "\n \n")); err == nil {
		t.Fatal("empty file must fail")
	}
	if _, err := readPassword(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestReadMarkedPassword(t *testing.T) {
	p := writeFile(t, "Title\n\nPassword of every archive: `pw-123`\nlast line\n")
	if got, err := readMarkedPassword(p, "Password of every"); err != nil || got != "pw-123" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := readMarkedPassword(p, "absent marker"); err == nil {
		t.Fatal("absent marker must fail")
	}
	if _, err := readMarkedPassword(writeFile(t, "Password: none here\n"), "Password"); err == nil {
		t.Fatal("unquoted must fail")
	}
	if _, err := readMarkedPassword(filepath.Join(t.TempDir(), "absent"), "x"); err == nil {
		t.Fatal("missing file must fail")
	}
}

func app(ws ...ax.Node) *ax.Node { return &ax.Node{Role: "AXApplication", Children: ws} }

func cell(title string) ax.Node { return ax.Node{Role: "AXGroup", Title: title} }

func mainWin(title string, cells ...string) ax.Node {
	g := ax.Node{Role: "AXGroup", Children: []ax.Node{{Role: "AXColumn", Title: "Name"}}}
	for _, c := range cells {
		g.Children = append(g.Children, cell(c))
	}
	return ax.Node{Role: "AXWindow", Subrole: "AXStandardWindow", Title: title, Children: []ax.Node{g}}
}

var passwordDialog = ax.Node{Role: "AXWindow", Subrole: "AXDialog", Children: []ax.Node{
	{Role: "AXStaticText", Value: "Enter the password:"},
	{Role: "AXTextField", Secure: true},
	{Role: "AXButton", Title: "OK"},
}}

func TestClassify(t *testing.T) {
	progress := ax.Node{Role: "AXWindow", Subrole: "AXUnknown", Children: []ax.Node{{Role: "AXProgressIndicator"}}}
	message := ax.Node{Role: "AXWindow", Subrole: "AXDialog", Children: []ax.Node{
		{Role: "AXStaticText", Value: "Cannot open"}, {Role: "AXButton", Title: "OK"},
		{Role: "AXButton", Subrole: "AXCloseButton"},
	}}
	start := ax.Node{Role: "AXWindow", Subrole: "AXStandardWindow", Title: "ZEDFREE", Children: []ax.Node{
		{Role: "AXStaticText", Value: "Drop a ZED! encrypted container here"}}}
	cases := []struct {
		name string
		tree *ax.Node
		want Kind
	}{
		{"password", app(passwordDialog, progress), KindPassword},
		{"busy", app(progress, start), KindBusy},
		{"message", app(message), KindMessage},
		{"opened", app(mainWin("ZEDFREE - a.zed", "x", "", "File 'TXT'", "d")), KindOpened},
		{"other archive open is not ours", app(mainWin("ZEDFREE - b.zed", "x", "", "File 'TXT'", "d")), KindNone},
		{"start", app(start), KindEmpty},
		{"nothing", app(), KindNone},
		{"textless dialog", app(ax.Node{Role: "AXWindow", Subrole: "AXDialog"}), KindNone},
	}
	for _, c := range cases {
		if got := Classify(c.tree, "a.zed"); got.Kind != c.want {
			t.Errorf("%s: %s, want %s", c.name, got.Kind, c.want)
		}
	}
	if got := Classify(app(message), "a.zed"); strings.Join(got.Texts, "|") != "Cannot open|[OK]" {
		t.Errorf("message texts %q", got.Texts)
	}
}

func TestRowsBothLayouts(t *testing.T) {
	rowWise := mainWin("t", "a", "1 KB", "File 'TXT'", "d1", "b", "", "Folder", "d2")
	columnWise := mainWin("t", "a", "b", "1 KB", "", "File 'TXT'", "Folder", "d1", "d2")
	want := []Row{{"a", "1 KB", "File 'TXT'", "d1"}, {"b", "", "Folder", "d2"}}
	for name, w := range map[string]ax.Node{"row": rowWise, "column": columnWise} {
		got := Rows(&w)
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] || got[0].IsFolder() || !got[1].IsFolder() {
			t.Errorf("%s: %v", name, got)
		}
	}
	odd := mainWin("t", "a", "b", "c")
	if Rows(&odd) != nil {
		t.Error("a ragged list must give no rows")
	}
	if Rows(&ax.Node{}) != nil {
		t.Error("no list, no rows")
	}
	if MainWindow(app(passwordDialog)) != nil || MainWindow(app(rowWise)) == nil {
		t.Error("MainWindow")
	}
}

func TestCompare(t *testing.T) {
	var b bytes.Buffer
	if !compare(&b, []string{"a", "b"}, nil) || !compare(&b, []string{"b", "a"}, []string{"a", "b"}) {
		t.Fatal("should match")
	}
	b.Reset()
	if compare(&b, []string{"a", "x"}, []string{"a", "b"}) {
		t.Fatal("should differ")
	}
	if !strings.Contains(b.String(), "MISSING b") || !strings.Contains(b.String(), "EXTRA x") {
		t.Fatalf("report: %s", b.String())
	}
}

func TestRefusesWithoutEnv(t *testing.T) {
	t.Setenv("ZED_GUI", "")
	cmd := RootCmd()
	cmd.SetArgs([]string{"check", "x.zed"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "ZED_GUI=1") {
		t.Fatalf("got %v", err)
	}
}
