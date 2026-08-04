package scoring

// Result is one submission's Phase 3 scoring record, keyed by the
// owning portal.Entry's ID. The automatic fields are computed once, at
// submit time (see AutoChecks and portal.SubmitHandler); the manual
// field is filled in later by an admin, via
// POST /admin/submissions/{id}/score, since prd.md's rubric includes
// one criterion — incident response quality — that this codebase has
// no way to observe automatically.
type Result struct {
	SubmissionID string `json:"submission_id"`

	// Scored is false until an exercise.Config existed to score
	// against at submit time — distinguishes "not yet scored" from
	// "scored zero" for the automatic fields below.
	Scored           bool           `json:"scored"`
	GenesisMatch     bool           `json:"genesis_match"`
	VersionSupported bool           `json:"version_supported"`
	LogWindow        LogWindowCheck `json:"log_window"`
	UploadTimeScore  int            `json:"upload_time_score"`
	MetadataScore    int            `json:"metadata_score"`
	LogQualityScore  int            `json:"log_quality_score"`

	IncidentResponseQualityScore *int `json:"incident_response_quality_score,omitempty"`
}

// Pending reports whether the manual criterion is still unentered,
// which makes TotalScore a lower bound rather than a final mark.
// Anything that shows a total to a human — the admin dashboard, the
// Discord summary — has to say so, or a half-scored submission is
// indistinguishable from a finished one.
func (r Result) Pending() bool {
	return r.IncidentResponseQualityScore == nil
}

// TotalScore sums every sub-score against prd.md's 100-point rubric.
// The manual field, if not yet entered, counts as 0 — callers that
// need to distinguish "not yet scored" from "scored zero" should check
// Scored and Pending rather than relying on TotalScore alone.
func (r Result) TotalScore() int {
	total := r.UploadTimeScore + r.MetadataScore + r.LogQualityScore
	if r.IncidentResponseQualityScore != nil {
		total += *r.IncidentResponseQualityScore
	}
	return total
}
