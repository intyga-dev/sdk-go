package intyga

// Private on-disk state for offline approval: the trust bundle, the redemption markers and the
// reconciliation buffer. Mirrors packages/sdk/src/secure-files.ts, so a directory written by one
// INTYGA SDK is read the same way by every other (docs/OFFLINE-APPROVAL-SDK.md, "Files").

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	privateFileMode fs.FileMode = 0o600
	privateDirMode  fs.FileMode = 0o700
)

// ensurePrivateDir creates (or repairs) a private directory, and refuses a path that is a symlink or
// not a directory.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, privateDirMode); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing unsafe directory: %s", dir)
	}
	// Windows and some network filesystems do not implement POSIX modes. Creation stays exclusive;
	// the containing volume must be protected there.
	_ = os.Chmod(dir, privateDirMode)
	return nil
}

// writePrivateFile atomically replaces file with contents, through an exclusive temporary file in the
// same directory, and refuses to replace a symlink or anything that is not a regular file.
func writePrivateFile(file string, contents []byte) error {
	dir := filepath.Dir(file)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	if info, err := os.Lstat(file); err == nil {
		if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing unsafe file: %s", file)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	id, err := randomUUID()
	if err != nil {
		return err
	}
	temp := filepath.Join(dir, fmt.Sprintf(".%s.%d.%s.tmp", filepath.Base(file), os.Getpid(), id))
	defer os.Remove(temp) // harmless after a successful rename
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
	if err != nil {
		return err
	}
	_, werr := f.Write(contents)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	_ = os.Chmod(temp, privateFileMode)
	if err := os.Rename(temp, file); err != nil {
		return err
	}
	_ = os.Chmod(file, privateFileMode)
	return nil
}

// createPrivateMarker creates file exactly once and reports whether THIS call created it.
//
// O_CREATE|O_EXCL is atomic on POSIX and on Windows: the OS refuses the open if the path exists — a
// symlink included, dangling or not — so two processes racing the same marker cannot both succeed.
// A stat-then-write check would lose that race, which is the whole point of the marker.
func createPrivateMarker(file, contents string) bool {
	if ensurePrivateDir(filepath.Dir(file)) != nil {
		return false
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
	if err != nil {
		return false
	}
	_, werr := f.WriteString(contents)
	_ = f.Chmod(privateFileMode)
	cerr := f.Close()
	return werr == nil && cerr == nil
}

// randomUUID returns a random RFC 4122 version-4 UUID, as crypto.randomUUID() does in the reference.
func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
