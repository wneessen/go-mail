package mail

import "testing"

// TestPartEncoding tests the WithPartEncoding and Part.SetEncoding methods
func TestPartEncoding(t *testing.T) {
	tests := []struct {
		name string
		enc  Encoding
		want string
	}{
		{"Part encoding: Base64", EncodingB64, "base64"},
		{"Part encoding: Quoted-Printable", EncodingQP, "quoted-printable"},
		{"Part encoding: 8bit", NoEncoding, "8bit"},
	}
	for _, tt := range tests {
		m := NewMsg()
		t.Run(tt.name, func(t *testing.T) {
			part := m.newPart(TypeTextPlain, WithPartEncoding(tt.enc), nil)
			if part == nil {
				t.Errorf("newPart() WithPartEncoding() failed: no part returned")
				return
			}
			if part.enc.String() != tt.want {
				t.Errorf("newPart() WithPartEncoding() failed: expected encoding: %s, got: %s", tt.want,
					part.enc.String())
			}
			part.enc = ""
			part.SetEncoding(tt.enc)
			if part.enc.String() != tt.want {
				t.Errorf("newPart() SetEncoding() failed: expected encoding: %s, got: %s", tt.want,
					part.enc.String())
			}
		})
	}
}
