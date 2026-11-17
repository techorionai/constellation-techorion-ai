package containers

import (
	"regexp"
	"testing"
)

// U5: each image has an exact version tag and a sha256 digest. The three
// references are the values of the plan.
func TestU5Images(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9./-]+:v?[0-9]+(\.[0-9]+)+(-[a-z0-9]+)?@sha256:[0-9a-f]{64}$`)
	want := map[string]string{
		"bifrost":  "maximhq/bifrost:v2.5.1@sha256:5ec9873acaf1687556b6e4dd854b92b539d9debf87a5a683b66338648b84d3c8",
		"postgres": "postgres:18.7-alpine@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015",
		"capture":  "nicolaka/netshoot:v0.14@sha256:7f08c4aff13ff61a35d30e30c5c1ea8396eac6ab4ce19fd02d5a4b3b5d0d09a2",
	}
	got := map[string]string{"bifrost": BifrostImage, "postgres": PostgresImage, "capture": CaptureImage}
	for name, ref := range got {
		if !re.MatchString(ref) {
			t.Errorf("%s: %q has no exact tag and sha256 digest", name, ref)
		}
		if ref != want[name] {
			t.Errorf("%s: got %q, want %q", name, ref, want[name])
		}
	}
	if len(Images()) != 3 {
		t.Errorf("Images() has %d entries, want 3", len(Images()))
	}
}
