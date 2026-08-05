package scoring

import "testing"

func TestResult_TotalScore_AutoOnly(t *testing.T) {
	r := Result{UploadTimeScore: 25, MetadataScore: 25, LogQualityScore: 25}
	if got := r.TotalScore(); got != 75 {
		t.Errorf("TotalScore() = %d, want 75 (manual field not yet entered counts as 0)", got)
	}
}

func TestResult_TotalScore_Full(t *testing.T) {
	irq := 18
	r := Result{
		UploadTimeScore:              25,
		MetadataScore:                25,
		LogQualityScore:              25,
		IncidentResponseQualityScore: &irq,
	}
	if got := r.TotalScore(); got != 93 {
		t.Errorf("TotalScore() = %d, want 93", got)
	}
}
