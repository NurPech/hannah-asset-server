//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// Target identity of the server process. The same uid/gid as the other Hannah
// containers (Timer, LogCollector, …).
const (
	runAsUID = 1000
	runAsGID = 1000
)

// dropPrivileges is the migration step for running the server as non-root.
//
// The image is FROM scratch (no shell, no chown entrypoint), and existing
// volumes were written by root. So the process starts as root, hands the
// storage directory to runAsUID:runAsGID and then drops to that identity
// before anything else (database, listener) is opened.
//
// If the process already runs as non-root (e.g. `user: 1000:1000` in the
// compose file), nothing is done.
//
// If the switch is not possible (NFS root_squash, dropped capabilities, …) the
// server keeps running as root and logs a warning, unless REQUIRE_NON_ROOT=true,
// in which case the error is returned and the caller should abort.
func dropPrivileges(storagePath string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	err := prepareAndDrop(storagePath, runAsUID, runAsGID)
	if err == nil {
		return nil
	}
	if os.Getenv("REQUIRE_NON_ROOT") == "true" {
		return err
	}
	log.Printf("WARNING: cannot switch to uid %d, continuing as root: %v", runAsUID, err)
	log.Printf("WARNING: fix the volume once with `chown -R %d:%d <volume>` and restart; set REQUIRE_NON_ROOT=true to make this fatal", runAsUID, runAsGID)
	return nil
}

func prepareAndDrop(storagePath string, uid, gid int) error {
	clean := filepath.Clean(storagePath)
	if clean == "/" || clean == "." {
		return fmt.Errorf("refusing to change ownership of %q", storagePath)
	}
	if err := os.MkdirAll(clean, 0o755); err != nil {
		return fmt.Errorf("create storage path: %w", err)
	}
	changed, err := fixOwnership(clean, uid, gid)
	if changed > 0 {
		log.Printf("changed ownership of %d entries below %s to %d:%d", changed, clean, uid, gid)
	}
	if err != nil {
		return fmt.Errorf("fix ownership of %s: %w", clean, err)
	}
	// Ground truth: can the target identity really create files here?
	// (NFS with squash mapping may accept chown but still show a different owner.)
	if err := canWriteAs(clean, uid, gid); err != nil {
		return fmt.Errorf("uid %d cannot write to %s: %w", uid, clean, err)
	}
	// Order matters: supplementary groups and gid need root, uid goes last.
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	log.Printf("dropped privileges to uid=%d gid=%d", uid, gid)
	return nil
}

// fixOwnership recursively gives root and everything below it to uid:gid and
// returns the number of entries it changed. Only entries with a differing
// owner are touched. The top-level directory is changed last and doubles as the
// "done" marker: if it already belongs to uid:gid the tree is considered
// migrated and not walked, so the normal start costs a single stat. An aborted
// run (error, crash) leaves the marker unset and is resumed on the next start.
func fixOwnership(root string, uid, gid int) (int, error) {
	if owned, err := ownedBy(root, uid, gid); err != nil {
		return 0, err
	} else if owned {
		return 0, nil
	}

	changed := 0
	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	chown := func(path string) {
		owned, err := ownedBy(path, uid, gid)
		if err != nil {
			fail(err)
			return
		}
		if owned {
			return
		}
		if err := os.Lchown(path, uid, gid); err != nil {
			fail(err)
			return
		}
		changed++
	}

	_ = filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			fail(err)
			return nil
		}
		if path != root {
			chown(path)
		}
		return nil
	})
	if firstErr != nil {
		return changed, firstErr
	}
	chown(root)
	return changed, firstErr
}

func ownedBy(path string, uid, gid int) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("no unix stat info")
	}
	return int(st.Uid) == uid && int(st.Gid) == gid, nil
}

// canWriteAs creates and removes a temporary file in dir with the filesystem
// identity uid:gid. fsuid/fsgid are per-thread, so the work runs on a locked
// thread that is never unlocked: when the goroutine ends, Go discards the
// thread together with its changed identity. Switching fsuid away from 0 also
// drops CAP_DAC_OVERRIDE for filesystem access, so root's bypass doesn't
// falsify the result.
func canWriteAs(dir string, uid, gid int) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		const none = ^uintptr(0)
		syscall.RawSyscall(syscall.SYS_SETFSGID, uintptr(gid), 0, 0)
		syscall.RawSyscall(syscall.SYS_SETFSUID, uintptr(uid), 0, 0)
		// passing an invalid id (-1) changes nothing and returns the current value
		if cur, _, _ := syscall.RawSyscall(syscall.SYS_SETFSUID, none, 0, 0); int(cur) != uid {
			result <- errors.New("cannot switch filesystem uid")
			return
		}
		f, err := os.CreateTemp(dir, ".writecheck-*")
		if err != nil {
			result <- err
			return
		}
		name := f.Name()
		f.Close()
		result <- os.Remove(name)
	}()
	return <-result
}
