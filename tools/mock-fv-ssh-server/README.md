# Mock FileVault SSH server

This development-only SSH server models observed FileVault pre-boot protocols.
Its default is the complete session captured from macOS 26.0.1; it can also
model a later prompt-only `OpenSSH_10.2` session. Use it to exercise `status`,
host-key enrollment, credential handling, and `unlock` without repeatedly
restarting a real Mac.

> [!CAUTION]
> This is a protocol test fixture, not a general SSH server or a FileVault
> replacement. Never give it a real password or expose it as a production
> service. It binds to loopback by default.

## What it models

In `locked` state, the server:

- advertises public-key, password, and keyboard-interactive authentication;
- accepts only one keyboard-interactive `Password:` response;
- emits the complete locked and success text from the captured Tahoe session by
  default, or only `Password:` before authentication when `--prompt-only` is
  set;
- returns an authentication failure and disconnects after the success text,
  matching the real FileVault server; and
- persists an Ed25519 host key so client host-key enrollment can be tested.

In `unlocked` state, it accepts public-key authentication to represent a booted
SSH server. `--authorized-key` can restrict that state to one public key; when
it is omitted, any public key is accepted by this loopback test fixture. A
password-only client still sees the same generic hidden `Password:` question as
a normal sshd. The mock does not provide a shell or SFTP service.

The mock does not advertise itself over Bonjour, start macOS, or reproduce every
OpenSSH feature. It remains locked by default, so use `unlock --no-verify` for a
single locked-state test. Use `--transition-on-unlock` to make subsequent
connections behave as booted, or restart it with `--state unlocked` and the
same host-key path.

## Quick test from the repository root

### 1. Build both binaries

On macOS, Linux, or a Windows Bash environment:

```bash
./build.sh --mock
```

Native PowerShell:

```powershell
New-Item -ItemType Directory -Force dist | Out-Null
Push-Location tools/mock-fv-ssh-server
go build -o ../../dist/mock-fv-ssh-server.exe .
Pop-Location
go build -o dist/fv-ssh-unlock.exe ./cmd/fv-ssh-unlock
```

### 2. Start the locked mock

In the first terminal:

```bash
MOCK_FV_PASSWORD='test-only-secret' \
  ./dist/mock-fv-ssh-server --port 2222 --username test --verbose
```

PowerShell:

```powershell
$env:MOCK_FV_PASSWORD = 'test-only-secret'
./dist/mock-fv-ssh-server.exe --port 2222 --username test --verbose
```

The default password is `password`, but setting a disposable value explicitly
makes the test setup unambiguous. Prefer `MOCK_FV_PASSWORD` or
`--password-file`; `--password` is visible in process listings and shell
history.

### 3. Configure and enroll the client

In a second terminal:

```bash
fv-ssh-unlock config add mock --host 127.0.0.1 --port 2222 --user test
fv-ssh-unlock status mock
fv-ssh-unlock status mock --accept-new-host-key
```

The first status command refuses the unknown key and prints its
SHA256 fingerprint. Compare it with the next server startup output before using
`--accept-new-host-key`, even in a local test.

### 4. Exercise unlock

Environment-variable build:

```bash
export FV_UNLOCK_PASSWORD_MOCK='test-only-secret'
fv-ssh-unlock unlock mock --no-verify
unset FV_UNLOCK_PASSWORD_MOCK
```

PowerShell:

```powershell
$env:FV_UNLOCK_PASSWORD_MOCK = 'test-only-secret'
fv-ssh-unlock.exe unlock mock --no-verify
Remove-Item Env:FV_UNLOCK_PASSWORD_MOCK
```

A keyring-enabled client can store the disposable password during `config add`
instead. `--no-verify` is required because the locked mock remains
in the locked test state after each connection.

## Test the prompt-only variant

A later real-hardware macOS 26 session advertised `OpenSSH_10.2` and presented
only the hidden `Password:` question. It did not send the explanatory locked
banner. Start that profile with:

```bash
MOCK_FV_PASSWORD='test-only-secret' \
  ./dist/mock-fv-ssh-server --port 2222 --username test \
  --prompt-only --server-version OpenSSH_10.2
```

PowerShell:

```powershell
$env:MOCK_FV_PASSWORD = 'test-only-secret'
./dist/mock-fv-ssh-server.exe --port 2222 --username test `
  --prompt-only --server-version OpenSSH_10.2
```

After enrolling the mock's host key, `status mock` should report `unknown`
because a generic password prompt cannot safely prove which SSH environment
answered. `unlock mock --no-verify` should still return `SUCCESS`. The version
string is not used as a lock-state signal.

## Test post-unlock verification

This mode changes the shared mock state after it sends the successful-unlock
message. The first connection still disconnects like FileVault; a later
connection can authenticate with the selected public key and produce the
client's `VERIFIED` result.

Start the server:

```bash
MOCK_FV_PASSWORD='test-only-secret' \
  ./dist/mock-fv-ssh-server --port 2222 --username test \
  --transition-on-unlock --authorized-key ~/.ssh/id_ed25519.pub
```

Then run the client after enrolling the mock host key:

```bash
export FV_UNLOCK_PASSWORD_MOCK='test-only-secret'
fv-ssh-unlock unlock mock --identity ~/.ssh/id_ed25519
unset FV_UNLOCK_PASSWORD_MOCK
```

PowerShell uses paths such as
`C:\Users\you\.ssh\id_ed25519.pub` and
`C:\Users\you\.ssh\id_ed25519`. If `--authorized-key` is omitted, any public
key is accepted in the unlocked state. That convenience is suitable only for
this loopback fixture.

## Run directly from the mock module

```bash
cd tools/mock-fv-ssh-server
go run . --port 2222
```

Or use a private password file:

```bash
chmod 600 ./test-password.txt
go run . --port 2222 --password-file ./test-password.txt
```

On Unix, password files must be private to the owner (mode `0600`). Password
sources `--password`, `--password-file`, and `MOCK_FV_PASSWORD` are mutually
exclusive.

## Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--bind` | `127.0.0.1` | Listen address. A non-loopback address requires an explicitly configured password and prints a warning. |
| `--port` | `8080` | TCP listening port. |
| `--state` | `locked` | Protocol state: `locked` or `unlocked`. |
| `--password` | `password` | Test password. Discouraged because it is process-visible. |
| `--password-file` | none | Read the test password from a private regular file. |
| `--username` | any | Require one SSH username when set. |
| `--host-key-path` | `mock_host_key` | Read or generate the persistent Ed25519 host key at this path. |
| `--banner` | captured Tahoe text | Override the locked explanation; set it to an empty string to reproduce the observed prompt-only variant. |
| `--prompt-only` | off | Omit the locked explanation and show only the hidden `Password:` question; overrides `--banner`. |
| `--transition-on-unlock` | off | Change subsequent connections to unlocked state after a correct FileVault password. |
| `--authorized-key` | any key | Public key file accepted in unlocked state. It is never accepted while locked. |
| `--success-message` | captured Tahoe text | Override the successful-unlock text. |
| `--server-version` | `OpenSSH_10.0` | Override the advertised SSH server version; `OpenSSH_10.2` was observed with the prompt-only variant. |
| `--verbose` | off | Log authentication outcomes without logging passwords. |

## Safety and maintenance

- Loopback is the safe default. Explicit `0.0.0.0`, `::`, or another external
  address exposes the fixture to the network.
- A non-loopback bind is refused when the default password is still in use.
- Password and host-key files must be regular files, are size-limited, and may
  not be symlinks. Private Unix permissions are enforced.
- Authorized public-key files must be regular, size-limited, non-symlink files;
  public permissions such as `0644` are allowed.
- CI builds, vets, race-tests, and vulnerability-scans this separate Go module.
- The executable and its protocol test share the same server configuration to
  prevent the documented handshake from drifting silently.

The redacted source transcript is
[`Tahoe 26.0 FileVault SSH Real Output.txt`](Tahoe%2026.0%20FileVault%20SSH%20Real%20Output.txt).
It contains no passwords or host keys.
