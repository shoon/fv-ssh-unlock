# Ansible examples

These examples install a locally built release binary and the hardened systemd
unit on an always-on Linux controller, then query its local v1 API. They do not
copy passwords or SSH private keys.

Set `fv_ssh_unlock_binary_source` to a verified binary matching the controller
architecture. Provision encrypted systemd credentials separately, preferably
with `systemd-creds`. List only their existing encrypted paths in
`fv_ssh_unlock_systemd_credentials`; the role writes the corresponding
`LoadCredentialEncrypted=` drop-in but never handles a plaintext value. Set
`fv_ssh_unlock_identity_credential` to the entry containing the dedicated
macOS SSH verification key.

```bash
ansible-playbook -i inventory.example.yml controller.yml
```

Set `fv_ssh_unlock_devices` to reconcile the strict non-secret JSON inventory;
leave it `null` to preserve an existing inventory. Runtime state and the staged
inventory are mode `0700`/`0600` and owned by the service account. The daemon's
reference-specific startup preflight fails closed if an auto-enabled
credential was not provisioned securely.

The role is intentionally small and transparent. Pin a released binary by
checksum in a real deployment rather than installing a mutable `latest` URL.
Its default binary path matches an extracted release archive; when running
from a source checkout after `./build.sh`, override it with
`{{ playbook_dir }}/../../dist/fv-ssh-unlock`.

Declarative device configuration does not establish SSH trust. Independently
verify and pin each Mac's host key through the enrollment ceremony before
expecting monitoring or automatic unlock to work. Do not turn a discovered
network key into an Ansible variable and treat that as independent evidence.
When an independently verified OpenSSH file is already maintained as trusted
infrastructure data, set `fv_ssh_unlock_known_hosts_source` and the role will
install it with service-only permissions. Leaving the variable `null`
preserves keys enrolled directly on the controller.
