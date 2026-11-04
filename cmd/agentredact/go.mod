module github.com/ChristopherDavenport/agentredact/cmd/agentredact

go 1.25.0

// The agentredact requirements name the version this module is released
// at, and the replaces below point at the tree so the release commit can
// name a version the proxy does not serve yet. Between releases make
// extracted skips this module, the tree having moved on from the version
// required; make check builds it against the tree.
require (
	github.com/ChristopherDavenport/agentredact v0.0.3
	github.com/ChristopherDavenport/agentredact/secrets v0.0.3 // indirect
	github.com/ChristopherDavenport/agentsession v0.0.37
)

require github.com/ChristopherDavenport/openresponses v0.0.18

require (
	github.com/ChristopherDavenport/agentpolicy v0.0.19 // indirect
	github.com/ChristopherDavenport/agenttool v0.0.29 // indirect
	github.com/ChristopherDavenport/agentturn v0.0.35 // indirect
)
