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

		sort.Slice(entries, func(i, j int) bool { return entries[i].Moniker < entries[j].Moniker })

		var b strings.Builder
		b.WriteString("## Validator Fire Drill — Summary\n\n")
		fmt.Fprintf(&b, "**Participation:** %d submission(s)\n\n", len(entries))

		for _, e := range entries {
			result, ok, err := scores.Get(e.ID)
			if err != nil {
				http.Error(w, "unable to read scoring record", http.StatusInternalServerError)
				return
			}

			fmt.Fprintf(&b, "- **%s** (%s) — ", e.Moniker, e.OperatorAddress)
			if !ok || !result.Scored {
				b.WriteString("not yet scored\n")
				continue
			}

			fmt.Fprintf(&b, "%d/100\n", result.TotalScore())
			if !result.GenesisMatch {
				b.WriteString("  - ⚠️ genesis_sha256 does not match the expected value\n")
			}
			if !result.VersionSupported {
				b.WriteString("  - ⚠️ gnoland_version is not in the supported list\n")
			}
			switch {
			case !result.LogWindow.Detected:
				b.WriteString("  - ⚠️ no recognizable timestamps found in gnoland.log.gz\n")
			case !result.LogWindow.Covered:
				b.WriteString("  - ⚠️ logs do not fully cover the investigation window\n")
			}
		}

		if cfg.Observations != "" {
			fmt.Fprintf(&b, "\n**Observations:**\n\n%s\n", cfg.Observations)
		}

		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	}
}
