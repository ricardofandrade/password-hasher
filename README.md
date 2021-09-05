# password-hasher

This repo implements as delayed-hashing HTTP service.

## Goal

The goal of this service is to transform plain-text passwords POST'ed to the 
`/hash` endpoint as a form field called `password` into a base64-encoded, 
SHA-512 hash.

However, this hash cannot be obtained immediately. Posting a password to `/hash`
merely returns a numerical ID. The service will only make the hash available
under `/hash/<id>` after a 5-second delay. Attempting to obtain a password hash
before this delay causes a 400 error. The hashed, encoded password is returned 
into the response body when available.

## Other functionality

The service provides a `/stats` endpoint that returns the `total` number of
hash operations initiated and the `average` time it took to complete them as a
JSON object.

This service supports remote stopping via the `/shutdown` endpoint. The graceful
shutdown may take up to 5 seconds if there's any pending passwords being hashed.

## Developing/Testing

This is a simple Go project, and it's easy to build and test it.
We should have a Go 1.15+ environment available for this project.

To build:
`go build`

To run:
`./password-hasher` (no options)

To (unit) test:
`go test ./...`

To test (integration):
`./test-more.sh`

> Note: test script requires a fresh instance. It will kill it at the end too.
> The integration test uses `bash`, `jq`, `curl`, `killall`, and `go`.
> These commands are required.
