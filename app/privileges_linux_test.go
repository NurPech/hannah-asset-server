//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (runs in CI and in the Docker integration test)")
	}
}

func owner(t *testing.T, path string) (int, int) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid)
}

// makeTree builds <root>/{a.db, ns/sub/file, link -> a.db}.
func makeTree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(filepath.Join(root, "ns", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a.db", "ns/sub/file"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("a.db", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	// uid 1000 must be able to traverse the whole temp path (t.TempDir parents are 0700)
	for p := filepath.Dir(root); p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestFixOwnership_NoopWhenAlreadyOwned(t *testing.T) {
	root := makeTree(t)
	n, err := fixOwnership(root, os.Getuid(), os.Getgid())
	if err != nil || n != 0 {
		t.Fatalf("got changed=%d err=%v, want 0/nil", n, err)
	}
}

func TestFixOwnership_MigratesRootOwnedTree(t *testing.T) {
	requireRoot(t)
	root := makeTree(t)
	paths := []string{root, filepath.Join(root, "a.db"), filepath.Join(root, "ns"),
		filepath.Join(root, "ns", "sub"), filepath.Join(root, "ns", "sub", "file"), filepath.Join(root, "link")}

	n, err := fixOwnership(root, runAsUID, runAsGID)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(paths) {
		t.Errorf("changed %d entries, want %d", n, len(paths))
	}
	for _, p := range paths {
		if u, g := owner(t, p); u != runAsUID || g != runAsGID {
			t.Errorf("%s owned by %d:%d, want %d:%d", p, u, g, runAsUID, runAsGID)
		}
	}
	// the symlink itself is changed, its target is not followed
	if n2, err := fixOwnership(root, runAsUID, runAsGID); err != nil || n2 != 0 {
		t.Errorf("second run changed=%d err=%v, want 0/nil", n2, err)
	}
}

func TestFixOwnership_ResumesWhenRootNotYetMarked(t *testing.T) {
	requireRoot(t)
	root := makeTree(t)
	// simulate an aborted run: a child is done, the top-level directory (the marker) is not
	if err := os.Lchown(filepath.Join(root, "a.db"), runAsUID, runAsGID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixOwnership(root, runAsUID, runAsGID); err != nil {
		t.Fatal(err)
	}
	if u, _ := owner(t, filepath.Join(root, "ns", "sub", "file")); u != runAsUID {
		t.Errorf("nested file not migrated, uid=%d", u)
	}
	if u, _ := owner(t, root); u != runAsUID {
		t.Errorf("root dir not migrated, uid=%d", u)
	}
}

func TestCanWriteAs(t *testing.T) {
	requireRoot(t)
	dir := makeTree(t)

	if err := canWriteAs(dir, runAsUID, runAsGID); err == nil {
		t.Error("root-owned 0755 dir must not be writable for uid 1000 (root's DAC override must not leak in)")
	}
	if err := os.Chown(dir, runAsUID, runAsGID); err != nil {
		t.Fatal(err)
	}
	if err := canWriteAs(dir, runAsUID, runAsGID); err != nil {
		t.Errorf("dir owned by uid 1000 must be writable: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 3 { // a.db, ns, link — temp file removed
		t.Errorf("temp file left behind: %v", entries)
	}
}

// ── Real privilege drop ──────────────────────────────────────────────────────
// The test binary re-executes itself as the "server" so the drop does not
// affect the test process.

const helperEnv = "HANNAH_TEST_DROP_HELPER"

// TestDropPrivilegesHelper is the child process; it does nothing in a normal run.
func TestDropPrivilegesHelper(t *testing.T) {
	path := os.Getenv(helperEnv)
	if path == "" {
		t.Skip("helper process only")
	}
	if err := dropPrivileges(path); err != nil {
		fmt.Printf("RESULT err=%v\n", err)
		return
	}
	fmt.Printf("RESULT uid=%d gid=%d\n", os.Geteuid(), os.Getegid())
}

func runDropHelper(t *testing.T, path string, env ...string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDropPrivilegesHelper$")
	cmd.Env = append(os.Environ(), append([]string{helperEnv + "=" + path}, env...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			return strings.TrimPrefix(line, "RESULT ")
		}
	}
	t.Fatalf("no RESULT line in helper output:\n%s", out)
	return ""
}

func TestDropPrivileges_MigratesAndDrops(t *testing.T) {
	requireRoot(t)
	root := makeTree(t) // existing install: everything owned by root
	got := runDropHelper(t, root)
	if want := fmt.Sprintf("uid=%d gid=%d", runAsUID, runAsGID); got != want {
		t.Fatalf("process identity after start: %q, want %q", got, want)
	}
	if u, g := owner(t, filepath.Join(root, "ns", "sub", "file")); u != runAsUID || g != runAsGID {
		t.Errorf("existing file owned by %d:%d after migration", u, g)
	}
}

func TestDropPrivileges_FreshInstall(t *testing.T) {
	requireRoot(t)
	root := filepath.Join(makeTree(t), "new") // does not exist yet
	if got := runDropHelper(t, root); !strings.HasPrefix(got, "uid=1000") {
		t.Fatalf("got %q", got)
	}
	if u, _ := owner(t, root); u != runAsUID {
		t.Errorf("new storage dir owned by uid %d", u)
	}
}

func TestDropPrivileges_FailOpenAndRequireNonRoot(t *testing.T) {
	requireRoot(t)
	// a storage path below a regular file cannot be created or chowned
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(file, "data")

	if got := runDropHelper(t, bad); got != "uid=0 gid=0" {
		t.Errorf("fail-open: got %q, want the process to stay root", got)
	}
	if got := runDropHelper(t, bad, "REQUIRE_NON_ROOT=true"); !strings.HasPrefix(got, "err=") {
		t.Errorf("REQUIRE_NON_ROOT: got %q, want an error", got)
	}
}

func TestDropPrivileges_RefusesFilesystemRoot(t *testing.T) {
	requireRoot(t)
	if got := runDropHelper(t, "/", "REQUIRE_NON_ROOT=true"); !strings.HasPrefix(got, "err=") {
		t.Errorf("got %q, want refusal", got)
	}
}
