package netattr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// CacheTTL is how long a downloaded range file is reused.
//
// Seven days is a compromise between accuracy and courtesy. Operators revise
// these files daily, but a prefix that moved yesterday is still almost always
// announced by the same operator, so the cost of week-old data is a slightly
// stale region rather than a wrong provider. The benefit is that auditing a
// portfolio does not pull several megabytes from four operators every run.
const CacheTTL = 7 * 24 * time.Hour

// maxRangeFileSize bounds a download. The largest of these publications is a
// few megabytes; anything far larger is a mistake or a hostile response, and
// reading it in full would let a third party exhaust this process's memory.
const maxRangeFileSize = 64 << 20

// CacheDir returns the directory range files are cached in.
func CacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("error: cannot determine the user cache directory: %w", err)
	}
	return filepath.Join(base, "dnsaudit", "netattr"), nil
}

// fetchCached returns a range file, from disk when it is fresh enough and from
// the network otherwise.
//
// A stale cache entry is preferred to a failed fetch. If an operator's endpoint
// is down, attributing addresses from last week's data is far better than
// attributing none — the alternative would silently reclassify every host as
// unattributed and remove findings that were correct yesterday.
func fetchCached(ctx context.Context, url string) ([]byte, error) {
	path, pathErr := cachePath(url)

	if pathErr == nil {
		if data, err := readIfFresh(path, CacheTTL); err == nil {
			return data, nil
		}
	}

	data, fetchErr := fetch(ctx, url)
	if fetchErr != nil {
		if pathErr == nil {
			if stale, err := readIfFresh(path, 0); err == nil {
				return stale, nil
			}
		}
		return nil, fetchErr
	}

	if pathErr == nil {
		// A cache that cannot be written is not an error worth failing on: the
		// data is in hand and the only cost is fetching it again next time.
		_ = writeCache(path, data)
	}
	return data, nil
}

// readIfFresh returns the cached file when it is younger than ttl. A ttl of
// zero accepts any age, which is how the stale fallback is expressed.
func readIfFresh(path string, ttl time.Duration) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if ttl > 0 && time.Since(info.ModTime()) > ttl {
		return nil, fmt.Errorf("cache entry is stale")
	}
	return os.ReadFile(path) //nolint:gosec // path is derived from a hash of a constant URL
}

func writeCache(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// Written to a temporary file and renamed, so a run interrupted mid-write
	// cannot leave a truncated file that parses to a partial range set.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cachePath names the cache entry after a hash of the URL, so that a URL
// containing path separators or query strings cannot escape the cache
// directory.
func cachePath(url string) (string, error) {
	dir, err := CacheDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".cache"), nil
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dnsaudit")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: %s returned HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxRangeFileSize))
}
