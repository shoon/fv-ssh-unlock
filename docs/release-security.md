# Release automation security boundaries

The package/release action is intended for the GitHub-hosted Ubuntu, macOS and
Windows runners used by these workflows. Runner event/output/summary files are
restricted to the corresponding hosted runner temporary directories, with
normalized directory containment and symlink checks. Self-hosted runners require
an explicitly reviewed path configuration rather than arbitrary RUNNER_TEMP.

HTTP downloads use explicit GitHub and Docker host allowlists, HTTPS, component
encoding, final encoded-path/query validation and size/time bounds. Redirects
cannot introduce another host or protocol and never forward Authorization or
Cookie headers. Docker's production.cloudfront.docker.com download host is
included because the current public registry redirects there. A future service
host change fails closed and needs an explicit reviewed allowlist update.
Repository API writes are confined to the current repository's fixed API root;
public upstream reads do not require cross-repository write credentials.

Semantic versions are length-bounded and parsed without a nested regular
expression. The tests include malformed/very long versions, URL and path
traversal, unapproved hosts, redirected command files, and unauthorized writes.
The complete guard suite contains 52 tests. These complement, rather than
replace, CodeQL, workflow linting, runtime release verification and real package
installation tests. No finding is suppressed by these changes.

Do not execute downloaded upstream source during verification. A valid signature
must identify the exact expected workflow and tag; tags must resolve to the
expected main history and both publishers must have passed on that source.
Package approval remains explicit and names the exact PR head. A successful
release or bottle publication is never rerun just to clear a status indicator.
