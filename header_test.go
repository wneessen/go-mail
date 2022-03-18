package mail

import (
	"testing"
)

// TestImportance_StringFuncs tests the different string method of the Importance object
func TestImportance_StringFuncs(t *testing.T) {
	tests := []struct {
		name   string
		imp    Importance
		wantns string
		xprio  string
		want   string
	}{
		{"Importance: Non-Urgent", ImportanceNonUrgent, "0", "5", "non-urgent"},
		{"Importance: Low", ImportanceLow, "0", "5", "low"},
		{"Importance: Normal", ImportanceNormal, "", "", ""},
		{"Importance: High", ImportanceHigh, "1", "1", "high"},
		{"Importance: Urgent", ImportanceUrgent, "1", "1", "urgent"},
		{"Importance: Unknown", 9, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.imp.NumString() != tt.wantns {
				t.Errorf("wrong number string for Importance returned. Expected: %s, got: %s",
					tt.wantns, tt.imp.NumString())
			}
			if tt.imp.XPrioString() != tt.xprio {
				t.Errorf("wrong x-prio string for Importance returned. Expected: %s, got: %s",
					tt.xprio, tt.imp.XPrioString())
			}
			if tt.imp.String() != tt.want {
				t.Errorf("wrong string for Importance returned. Expected: %s, got: %s",
					tt.want, tt.imp.String())
			}
		})
	}
}
