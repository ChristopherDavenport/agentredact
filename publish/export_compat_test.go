package publish

import (
	"context"

	"github.com/ChristopherDavenport/agentsession"
)

// exportFrom is ExportDataset with the test profile's rules.
func exportFrom(ctx context.Context, st agentsession.Store, m Manifest, dir string, opts Options) error {
	return ExportDataset(ctx, st, m, dir, opts, profile.StringFunc())
}
