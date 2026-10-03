package bench

import (
	"fmt"
	"math"
	"testing"
)

func TestSplitIsDeterministicAndProportional(t *testing.T) {
	calib := 0
	const n = 100000
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("s%06d", i)
		first, second := SplitOf(id), SplitOf(id)
		if first != second {
			t.Fatal("split must be deterministic")
		}
		if first == SplitCalibration {
			calib++
		}
	}
	if share := float64(calib) / n; math.Abs(share-0.30) > 0.01 {
		t.Fatalf("calibration share = %.3f, want ~0.30", share)
	}
	if !InSplit("s000001", SplitAll) {
		t.Fatal("SplitAll must match every sample")
	}
}

func TestEveryLabelIsMapped(t *testing.T) {
	for _, l := range Labels() {
		cats, err := CategoriesFor(l)
		if err != nil || (l != Benign && len(cats) == 0) {
			t.Errorf("label %s: cats=%v err=%v", l, cats, err)
		}
	}
	if _, err := CategoriesFor("nope"); err == nil {
		t.Error("unknown label must fail")
	}
}
