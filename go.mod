module github.com/ChristopherDavenport/agentredact

go 1.25.0

// The secrets requirement names the version this module is released
// at, and the replace below points at the tree so the release commit
// can name a version the proxy does not serve yet. Consumers ignore the
// replace and get the require; make extracted builds the module with
// it dropped, the way a consumer does.
require (
	github.com/ChristopherDavenport/agentpolicy v0.0.17
	github.com/ChristopherDavenport/agentredact/secrets v0.0.1
	github.com/ChristopherDavenport/agentsession v0.0.28
	github.com/ChristopherDavenport/openresponses v0.0.14
)

require (
	github.com/ChristopherDavenport/agenttool v0.0.22 // indirect
	github.com/ChristopherDavenport/agentturn v0.0.24 // indirect
)

replace github.com/ChristopherDavenport/agentredact/secrets => ./secrets
