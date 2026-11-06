# pickup-relay

The SMTP pickup relay sidecar: `ghcr.io/olljanat-ai/containerizer-pickup-relay`. An application that writes mail
as `.eml` files into a pickup folder (`SmtpDeliveryMethod.SpecifiedPickupDirectory`), where an IIS SMTP service
on the Windows server used to send them, runs unchanged in a pod: the generator mounts a shared `emptyDir` at
the folder in the app and in this sidecar, which sends each file to the relay (docs/platform-fixes.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `SMTP_HOST` | (required) | the SMTP relay |
| `SMTP_PORT` | 587 (465 implicit TLS, 25 without TLS) | its port |
| `SMTP_TLS` | `starttls` | `starttls` (required), `implicit` (SMTPS), `opportunistic`, `none` |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | | AUTH PLAIN, only over TLS |
| `SMTP_HELO` | `pickup-relay` | EHLO name |
| `PICKUP_DIR` | `/pickup` | the folder the app writes to |
| `POLL_INTERVAL` | `5s` | how often the folder is read |
| `SETTLE_TIME` | `2s` | a file younger than this may still be being written |
| `KEEP_SENT` | `true` | move sent files to `sent/` (`false`: delete them) |
| `ONCE` | `false` | one pass, then exit (1 if anything was not sent) |

The envelope comes from the `X-Sender` / `X-Receiver` lines that .NET and IIS write at the top of a pickup file
(they are removed before sending, as the IIS SMTP service did), or else from `From` / `Sender` and `To`, `Cc`,
`Bcc`; a `Bcc` header is never sent. A file the relay refuses for good (5xx, an unreadable message) moves to
`failed/` with a `.error` file beside it; a temporary failure (connection refused, 4xx) stays in the folder
and is sent again on the next pass. Logs are JSON lines on stdout.

Tests: `go test ./...` (the image build runs them too).
