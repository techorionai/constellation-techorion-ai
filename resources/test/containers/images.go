// Package containers has the Docker setup of the integration tests of Bifrost:
// the network, PostgreSQL, the capture container, and Bifrost in the network
// namespace of the capture container.
package containers

// Image references. Each reference has an exact version tag and the sha256
// digest of the image index. Change an image here only.
const (
	// BifrostImage is the upstream Bifrost image. The tool does not build an
	// own image.
	BifrostImage = "maximhq/bifrost:v2.5.1@sha256:5ec9873acaf1687556b6e4dd854b92b539d9debf87a5a683b66338648b84d3c8"
	// PostgresImage is the PostgreSQL image. The tag is the same as the tag in
	// constellation-deploy.
	PostgresImage = "postgres:18.7-alpine@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015"
	// CaptureImage is the image of the capture container and of the helper
	// container of the positive control.
	CaptureImage = "nicolaka/netshoot:v0.14@sha256:7f08c4aff13ff61a35d30e30c5c1ea8396eac6ab4ce19fd02d5a4b3b5d0d09a2"
)

// Images returns all image references of this package.
func Images() []string {
	return []string{BifrostImage, PostgresImage, CaptureImage}
}
