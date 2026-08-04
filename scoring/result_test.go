package scoring

import "testing"

func TestResult_TotalScore_AutoOnly(t *testing.T) {
	r := Result{UploadTimeScore: 20, MetadataScore: 20, LogQualityScore: 20}
	if got := r.TotalScore(); got != 60 {
		t.Errorf("TotalScore() = %d, want 60 (manual fields not yet entered count as 0)", got)
	}
}

func TestResult_TotalScore_Full(t *testing.T) {
	ack, irq := 15, 18
	r := Result{
		UploadTimeScore:              20,
		MetadataScore:                20,
		LogQualityScore:              20,
		AckTimeScore:                 &ack,
		IncidentResponseQualityScore: &irq,
	}
	if got := r.TotalScore(); got != 93 {
		t.Errorf("TotalScore() = %d, want 93", got)
	}
}
