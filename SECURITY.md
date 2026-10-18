# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it
privately through GitHub's vulnerability reporting form:

https://github.com/ChristopherDavenport/agentredact/security/advisories/new

Include the affected version, a description of the issue and, if you
have one, a minimal reproduction made of synthetic data; never attach a
real session or a real secret. You will get an acknowledgement within a
week. Once a fix is available it ships as a new patch version and the
advisory is published with credit to the reporter, unless you prefer to
stay anonymous.

## Supported versions

Only the latest release receives security fixes.

## Scope

This module reads private sessions, which hold whole conversations,
tool arguments and tool output, and writes the copies meant to leave.
In scope is anything that makes a redaction miss what it was told to
remove: a string a redactor's rules match left in any member, record,
media item, blob or header of a redacted session or its ATIF export,
or an original hash kept that confirms a redacted value. Also in scope
is anything that lets an unredacted entry, or an original session,
reach a published store or a dataset export, past the scan, the review
or a store set to hold only redacted entries. What the plan documents
as not found (values encoded in base64 or URL encoding, text in image
bytes) is a known limit, not a vulnerability; a crafted session that
crashes the command or exhausts its memory is in scope too.
