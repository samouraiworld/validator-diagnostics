// Package submission validates fire-drill archive submissions against
// the rules in prd.md: the "<moniker>-<YYYYMMDD-HHMMUTC>.tar.gz" naming
// convention, the "gnoland.log.gz" + "metadata.json" archive structure,
// and the hardening rules under "Security Considerations" (no path
// traversal, no symlinks, no unexpected entries, bounded decompression).
//
// This package only validates — it never writes anywhere and never
// executes/interprets archive content. Storing a validated archive is a
// separate step (see the storage package).
package submission

import (
	"fmt"
	"regexp"
	"time"
)

// filenameRe splits "<moniker>-<YYYYMMDD-HHMMUTC>.tar.gz". The moniker
// group is greedy so monikers containing hyphens (e.g.
// "samourai-eu-1") are still split correctly: regex backtracking finds
// the rightmost split where the suffix still matches the fixed
// timestamp pattern.
var filenameRe = regexp.MustCompile(`^(.+)-(\d{8}-\d{4}UTC)\.tar\.gz$`)

// monikerCharsRe restricts the moniker to characters safe to use
// unescaped as part of an object storage key.
var monikerCharsRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

const timestampLayout = "20060102-1504UTC"

// ValidateFilename checks name against the
// "<moniker>-<YYYYMMDD-HHMMUTC>.tar.gz" convention (prd.md, "Standard
// Submission Format") and returns the parsed moniker and timestamp.
func ValidateFilename(name string) (moniker string, submittedAt time.Time, err error) {
	m := filenameRe.FindStringSubmatch(name)
	if m == nil {
		return "", time.Time{}, fmt.Errorf("archive name %q does not match <moniker>-<YYYYMMDD-HHMMUTC>.tar.gz", name)
	}

	moniker, tsPart := m[1], m[2]

	if !monikerCharsRe.MatchString(moniker) {
		return "", time.Time{}, fmt.Errorf("archive name %q: moniker %q contains disallowed characters", name, moniker)
	}

	submittedAt, err = time.Parse(timestampLayout, tsPart)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("archive name %q: invalid timestamp %q: %w", name, tsPart, err)
	}

	return moniker, submittedAt, nil
}
