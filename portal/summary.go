package portal

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/scoring"
)

// AdminSummaryHandler serves GET /admin/summary: a Markdown-formatted
// report — participation, per-submission status and score, validation
// warnings, and free-text observations — matching what prd.md's Phase
// 3 asks to be "published on Discord (or another communication
// channel)". Publishing itself stays a manual admin action; this only
// generates the text. Wrap with AdminAuth.
func AdminSummaryHandler(log *FileLog, exerciseStore *exercise.FileStore, scores *scoring.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		entries, err := log.Entries()
		if err != nil {
			http.Error(w, "unable to read submissions", http.StatusInternalServerError)
			return
		}
		cfg, err := exerciseStore.Get()
		if err != nil {
			http.Error(w, "unable to read exercise config", http.StatusInternalServerError)
			return
		}

		// One read for the whole join — see AdminSubmissionsHandler. It
		// matters more here: the summary is published, so the rows have to
		// describe one consistent moment rather than a walk across
		// however many the scoring file went through while it rendered.
		results, err := scores.ByID()
		if err != nil {
			http.Error(w, "unable to read scoring records", http.StatusInternalServerError)
			return
		}

		sort.Slice(entries, func(i, j int) bool { return entries[i].Moniker < entries[j].Moniker })

		var b strings.Builder
		b.WriteString("## Validator Fire Drill — Summary\n\n")
		fmt.Fprintf(&b, "**Participation:** %d submission(s)\n\n", len(entries))

		for _, e := range entries {
			result, ok := results[e.ID]

			fmt.Fprintf(&b, "- **%s** (%s) — ", e.Moniker, e.OperatorAddress)
			if !ok || !result.Scored {
				b.WriteString("not yet scored\n")
				continue
			}

			fmt.Fprintf(&b, "%d/100%s\n", result.TotalScore(), pendingNote(result))
			if !result.GenesisMatch {
				b.WriteString("  - ⚠️ genesis_sha256 does not match the expected value\n")
			}
			if !result.VersionSupported {
				b.WriteString("  - ⚠️ gnoland_version is not in the supported list\n")
			}
			// Exactly one line, because the truncated case is not a weaker
			// version of the uncovered case: it is the absence of a verdict.
			// Emitting both would state as fact that the validator's logs
			// fall short of the window and then immediately admit we never
			// looked. Informational, deliberately not a ⚠️ warning — the
			// scan stopping early is a limit of this tool, not something
			// the validator did wrong.
			switch {
			case !result.LogWindow.Detected:
				b.WriteString("  - ⚠️ no recognizable timestamps found in validator.log.gz\n")
			case result.LogWindow.Truncated:
				b.WriteString("  - ℹ️ log coverage could not be fully verified: the scan stopped before the end of the log\n")
			case !result.LogWindow.Covered:
				b.WriteString("  - ⚠️ logs do not fully cover the investigation window\n")
			}

			// Same one-line-at-most discipline as above. A validator who
			// runs no sentry and says so is not flagged at all: there is
			// nothing there to report, and the missing points already say
			// it in the total.
			switch {
			case !result.SentryLogPresent:
				if e.SentryEnabled {
					b.WriteString("  - ℹ️ no sentry.log.gz submitted (sentry_enabled is true)\n")
				}
			case !result.SentryLogWindow.Detected:
				b.WriteString("  - ⚠️ no recognizable timestamps found in sentry.log.gz\n")
			case result.SentryLogWindow.Truncated:
				b.WriteString("  - ℹ️ sentry log coverage could not be fully verified: the scan stopped before the end of the log\n")
			case !result.SentryLogWindow.Covered:
				b.WriteString("  - ⚠️ sentry logs do not fully cover the investigation window\n")
			}
		}

		if cfg.Observations != "" {
			fmt.Fprintf(&b, "\n**Observations:**\n\n%s\n", cfg.Observations)
		}

		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	}
}

// pendingNote qualifies a total that isn't final yet. This text gets
// pasted into Discord, so a submission still missing its manually
// entered criterion must not read as a finished "75/100" — it is 75
// out of the points awarded so far.
func pendingNote(r scoring.Result) string {
	if r.IncidentResponseQualityScore == nil {
		return " (incident response pending)"
	}
	return ""
}
