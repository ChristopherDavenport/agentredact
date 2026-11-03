package agentredact

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/ChristopherDavenport/agentsession"
)

// Key is the secret a redaction names sessions under (agentsession RFC
// 0001, The redacted session, since format 0.19): a redacted session's
// redacted_from names its original by the original's keyed pseudonym,
// and its ID, and every reference into another session, derive from
// that pseudonym, so someone holding a native session ID cannot find
// which published redaction was made from it.
//
// One key belongs to a store of originals, and its holder keeps it
// beside that store, never with what is published: it is no member of
// any session, profile, report or manifest, and a Key never prints its
// bytes ([Key.String], [Key.GoString], [Key.LogValue]) or marshals them.
// Every redaction of one store uses the one key, so a reference to a
// session derives one ID in every redacted session of a profile, and a
// redaction run again derives the same ID and resumes. A key is not
// recoverable: whoever loses it cannot resume the redactions made under
// it, and starts new redacted sessions under a new key, which a store
// pass then writes beside the old ones.
//
// The zero Key holds nothing, and [Redact] and [RedactStore] refuse it
// with [agentsession.ErrRedactionKey]: there is no default key.
type Key struct {
	b []byte
}

// NewKey returns a Key holding a copy of b, which must be at least
// [agentsession.RedactionKeySize] (32) random bytes; a shorter one is
// refused with [agentsession.ErrRedactionKey].
func NewKey(b []byte) (Key, error) {
	if len(b) < agentsession.RedactionKeySize {
		return Key{}, agentsession.ErrRedactionKey
	}
	return Key{b: bytes.Clone(b)}, nil
}

// GenerateKey returns a new Key of 32 bytes from crypto/rand.
func GenerateKey() (Key, error) {
	b := make([]byte, agentsession.RedactionKeySize)
	if _, err := rand.Read(b); err != nil {
		return Key{}, fmt.Errorf("agentredact: generating a key: %w", err)
	}
	return Key{b: b}, nil
}

// valid reports whether k holds a key.
func (k Key) valid() error {
	if len(k.b) < agentsession.RedactionKeySize {
		return agentsession.ErrRedactionKey
	}
	return nil
}

// String names a key without its bytes.
func (k Key) String() string {
	if k.b == nil {
		return "agentredact.Key(none)"
	}
	return "agentredact.Key(…)"
}

// GoString is String, so %#v does not print the bytes either.
func (k Key) GoString() string { return k.String() }

// LogValue is the key for log/slog: String, never the bytes.
func (k Key) LogValue() slog.Value { return slog.StringValue(k.String()) }

// errKeyMarshal is what a Key's MarshalText returns.
var errKeyMarshal = errors.New("agentredact: a redaction key is not marshalled; it stays in its key file")

// MarshalText refuses: a key is written only by [WriteKeyFile], so no
// encoder of a struct holding one writes it out by accident.
func (k Key) MarshalText() ([]byte, error) { return nil, errKeyMarshal }

// RedactedID is the ID of the redaction of a native original, one whose
// header is not itself a redacted session's, under key and profile: the
// ID [Redact] gives its redacted session and that every reference to
// the original derives. It is [agentsession.RedactedSessionID] of the
// original's [agentsession.Pseudonym], the derivation RFC 0001
// recommends since 0.19. A zero key gives "".
func RedactedID(key Key, original, profile string) string {
	ps, err := agentsession.Pseudonym(key.b, original, profile)
	if err != nil {
		return ""
	}
	return agentsession.RedactedSessionID(ps, profile)
}

// names are the names a redaction of original writes under key and
// profile.
func (k Key) names(original *agentsession.Session, profile string) (*agentsession.RedactionNames, error) {
	if err := k.valid(); err != nil {
		return nil, err
	}
	return agentsession.NewRedactionNames(k.b, original, profile)
}

// keyFilePrefix starts a key file, so a file that is not one is told
// apart from one that is damaged.
const keyFilePrefix = "agentredact-key-v1:"

// ErrKeyFile is returned by [ReadKeyFile] for a file that does not hold
// a key, or that others than its owner may read, and by [WriteKeyFile]
// for a path that holds a file already.
var ErrKeyFile = errors.New("agentredact: key file")

// WriteKeyFile writes k to a new file at path, readable and writable by
// its owner alone (0600), as one line: "agentredact-key-v1:" and the key
// in hex. It refuses a path that exists, so a key is never overwritten:
// an overwritten key is a lost one, and the redactions made under it can
// no longer be resumed. Keep the file beside the store of originals, out
// of any repository, dataset or log, and back it up as you back up the
// originals.
func WriteKeyFile(path string, k Key) error {
	if err := k.valid(); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %s exists; a key is never overwritten", ErrKeyFile, path)
	}
	if err != nil {
		return fmt.Errorf("agentredact: writing the key file: %w", err)
	}
	_, werr := f.WriteString(keyFilePrefix + hex.EncodeToString(k.b) + "\n")
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("agentredact: writing the key file: %w", err)
	}
	return nil
}

// ReadKeyFile reads the key [WriteKeyFile] wrote at path. On a system
// with Unix permissions it refuses a file that its group or others may
// read or write, as ssh refuses a private key so kept: the key is a
// secret, and a file others can read has already shared it. A missing
// file is an error wrapping [fs.ErrNotExist]; there is no default key
// to fall back to.
func ReadKeyFile(path string) (Key, error) {
	f, err := os.Open(path)
	if err != nil {
		return Key{}, fmt.Errorf("agentredact: reading the key file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Key{}, fmt.Errorf("agentredact: reading the key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Key{}, fmt.Errorf("%w: %s is not a regular file", ErrKeyFile, path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Key{}, fmt.Errorf("%w: %s is open to others (mode %v); chmod 600 it", ErrKeyFile, path, info.Mode().Perm())
	}
	data := make([]byte, 4096)
	n, err := f.Read(data)
	if err != nil {
		return Key{}, fmt.Errorf("agentredact: reading the key file: %w", err)
	}
	line := strings.TrimRight(string(data[:n]), "\r\n")
	enc, ok := strings.CutPrefix(line, keyFilePrefix)
	if !ok || strings.ContainsAny(enc, "\r\n") {
		return Key{}, fmt.Errorf("%w: %s does not hold a key", ErrKeyFile, path)
	}
	b, err := hex.DecodeString(enc)
	if err != nil {
		return Key{}, fmt.Errorf("%w: %s does not hold a key", ErrKeyFile, path)
	}
	k, err := NewKey(b)
	if err != nil {
		return Key{}, fmt.Errorf("%w: %s: %w", ErrKeyFile, path, err)
	}
	return k, nil
}

// OriginalOf finds, in st, the original the redacted session s was made
// from and maps each of s's own entries to the original's entries it
// was made from, for the holder of key: s's redacted_from names the
// original by its keyed pseudonym, which only the key resolves. It is
// [agentsession.OriginalUnder] under key.
func OriginalOf(ctx context.Context, st agentsession.Store, key Key, s *agentsession.Session) (*agentsession.Session, map[string][]string, error) {
	if err := key.valid(); err != nil {
		return nil, nil, err
	}
	return agentsession.OriginalUnder(ctx, st, key.b, s)
}
