<!--
PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
written-by: codex/gpt-6 | 2026-11-13 | :/isolate-capstone-sources-v1
modified-by: codex/gpt-6 | 2026-11-13 | 9c5efd8b0424542d2759043bbb402e9a51d58c27
reviews: pending current exact-commit claude-code and grok-build approval
END PROVENANCE
-->
# Capstone source isolation on Linux

`guard-run` is a companion execution boundary. `guard-gate` still only returns
advisory ALLOW/DENY/REVIEW decisions; neither it, `guard-perm`, nor `guard-scan`
intercepts an agent's filesystem operations. Their interfaces are unchanged.

## Supported host and installation

Use a maintained Linux distribution on x86-64 or AArch64, Python 3.10+, kernel
5.6+ with `openat2`, sealed memfds, procfs, and enabled unprivileged user, mount,
PID, IPC, UTS and network namespaces. Bubblewrap **0.9.0+** must be a trusted,
root-owned, non-setuid executable at `/usr/bin/bwrap`, without group/other write
permission. The launcher refuses root. The actual namespace probe, rather than
the version numbers, determines whether the host is usable.

Ubuntu 24.04 installation prerequisites (operator commands; the runner installs
nothing and changes no system settings):

```sh
sudo apt-get update
sudo apt-get install bubblewrap python3 python3-venv
python3 -m venv .venv
.venv/bin/python -m pip install .
/usr/bin/bwrap --version
```

The bind-mount test asks Bubblewrap to construct a synthetic adversarial nested
mount during setup, then runs its resolution check with capabilities dropped.
It needs no separate `mount` or `unshare` helper and changes no host mount or
security policy. Existing permission tests use `acl` when available.
The example assumes a merged `/usr` containing `/usr/bin/python3` and its
stdlib/libraries. `/bin`, `/sbin`, `/lib`, `/lib64` point into that runtime.
Non-merged systems need a separately prepared merged runtime directory.
An additional curated runtime can be mounted at `/opt/runtime`.

LSM/AppArmor, container seccomp profiles, or site policy can forbid namespaces
even on recent kernels. **Do not disable those host protections or change
desktop account/service/provider settings to make this work.** Run on a suitable
dedicated Linux host or VM and require preflight success there. No advisory
fallback exists.

## Exact synthetic launch

From the checkout, create a previously nonexistent directory:

```sh
.venv/bin/python examples/make_synthetic_policy.py /tmp/capstone-demo
.venv/bin/guard-run check --policy /tmp/capstone-demo/policy.json
.venv/bin/guard-run run --policy /tmp/capstone-demo/policy.json -- \
  /usr/bin/python3 -I -c 'from pathlib import Path; Path("/out/result.txt").write_bytes(Path("/inputs/public/cleared.txt").read_bytes())'
cat /tmp/capstone-demo/out/result.txt
```

`check` must exit 0 and report `{"event":"check","status":"enforceable","code":0}`
(JSON whitespace may differ). It launches an actual restricted Python process
and checks separate namespaces, a readable synthetic input, an existing host
canary that must be unreadable, allowed writes, denied writes, zero effective
capabilities and `no_new_privs`. It also validates every requested input digest
and writable root. `run` repeats preflight and probes again in the agent's own
namespace before executing the command. This does not test provider availability
or predict all of an agent's runtime dependencies.

Invocation/policy/prerequisite/probe failures exit **125**, with a fixed reason
code on stderr. An executed command's exit status is returned (it can itself
return 125). A missing Bubblewrap reports `bubblewrap_missing`; a kernel/path
resolution failure reports `unsafe_or_unavailable_path_resolution`; namespace
or isolated runtime failures report `isolation_probe_failed`. In the last case,
verify the required namespace permissions and runtime dependencies on the chosen
host. Commands never run when preflight fails.

`python3 -m guardlib.runner check|run --policy ...` works from a checkout too.
The launched command must use an absolute **sandbox** path. This is a batch
runner: stdin is `/dev/null`; no desktop terminal/session is inherited.

## Source policy

The generated policy is also shown in
[`examples/capstone.policy.json`](../examples/capstone.policy.json). A manifest
entry has a relative path, exact SHA-256 and one of these two clearance labels:

| Classification | Exposure |
| --- | --- |
| `PUBLIC/ALT` | Only individually approved, digest-matching files |
| `NOTES` | Only individually approved, digest-matching files |
| `LICENSED` | Never an accepted manifest classification |
| Missing or new/unclassified | Not mounted; reads fail |

`LICENSED` includes Westlaw, Lexis, Gallagher, ILL and other library material.
Public availability is not clearance. Never add licensed material to a manifest,
runtime, credential, agent argument, model weights containing research, or output
root. Notes must be the owner's cleared interpretations, not a workaround for
passing licensed excerpts. The runner does not decide copyright or classification.

The trusted operator explicitly approves a file and records its SHA-256; do not
automate blanket approval or scanning of a mixed research tree. A changed file
requires fresh clearance and digest approval. Unlisted files remain invisible
even when added underneath an approved input root. Roots and all their path
components must be real directories without symlinks. Listed inputs must be
single-link regular files; symlinks, hard links, FIFOs, devices and sockets fail
before content is exposed to the agent. Input roots may be explicit filesystem
mount points; traversal into a mount **below** them is rejected atomically.

The launcher reads listed files to verify their hashes and builds sealed,
read-only snapshots. It never reads unlisted source files. Only snapshots enter
the namespace at `/inputs/ID/relative-path`; the original input directories and
their host paths are not mounted. No licensed documents or real credentials
are supplied in this repository, examples or tests. The example generator
creates only synthetic fixtures and refuses an existing destination. The runner
never moves, deletes or reclassifies research sources.

## Runtime, writes and policy ownership

Runtime roots are a separate explicit clearance of **trusted software**, not
research input trees. The `/usr` example exposes all of that software tree
read-only, including installed documentation. It must contain no research,
secrets, host-service sockets or source-reading brokers. A host that stores
research there must use a separate clean runtime image instead. The runner
cannot recognize licensed content placed in an operator-approved runtime.
Runtime directories remain live mounts: trusted host updates must not race a
session. Runtime and writable roots reject nested mounts and are pinned by
directory descriptors before mounting. Whole `/`, home and common broad host
roots are refused as runtimes. No implicit host `/etc`, home, Nextcloud tree,
`/run`, SSH agent, D-Bus, Docker socket or GPU devices are exposed.

`writable` must specify three distinct, non-overlapping, **empty**, owner-owned
0700 directories, mounted at `/out`, `/cache` and `/tmp`. They cannot overlap
source/runtime roots or contain the policy. Use new directories and a new policy
per run; reuse is refused, including caches, to avoid importing unclassified
leftovers or pre-existing hard links/sockets. The runner never empties old roots.
Files produced there are untrusted outputs; do not execute them on the host.

Persistent host writes are restricted to these roots. The root filesystem,
inputs and runtimes are read-only. Private procfs and minimal `/dev` expose
kernel process/device interfaces, not host research files; `/dev/null`, random
devices, and private `/dev/shm` are exceptions to ordinary file-write tests.
They are not additional persistent host storage. No host block devices are
mounted. The launcher itself creates only a private temporary setup directory,
synthetic canary, in-memory snapshots, and the approved output artifacts.

The policy must be an owner-owned, single-link regular file without group/other
write permission (0600 is recommended). Unknown keys, duplicate keys, overlapping
roots, unknown labels, and bad digests fail closed. Policy is parsed once by the
trusted launcher and is not mounted. The child cannot change that launcher's
policy by writing a new file or environment variable. Even a nested invocation
of Bubblewrap cannot acquire host mounts: all capabilities are dropped,
`no_new_privs` prevents setuid/file-capability elevation, and further user
namespaces are disabled and asserted disabled. Mount/setns/unshare escape
attempts are exercised by the tests.

Only setup descriptors are explicitly passed to Bubblewrap; Bubblewrap closes
them before the agent. All other inherited FDs (including source files, sockets,
directory handles), cwd, stdin and environment are discarded. Stdout/stderr are
new files within `/out`, not inherited host file descriptors. PID and network
namespaces remove host `/proc/PID/root`, `/proc/PID/fd`, loopback services and
abstract Unix sockets as alternate access paths. Symlinks created by the agent
resolve within its restricted filesystem; hard links cannot name an absent host
inode. Traversal never restores the old root.

## Offline, local inference and online agents

`{"mode":"none"}` is the default example. There is a private network namespace
with no host interface or external route. Child processes and local model
servers **started inside the same invocation** inherit the boundary. Run a
supervisor script that starts both the CPU inference server and agent in this
namespace, using localhost there. Approve model weights and code as individual
inputs, or curate model software in the runtime. Host inference servers, MCP
servers with filesystem tools, desktop agents, browser automation outside this
runner, remote tool workers and already-running processes are **outside the
boundary** and must not be connected as source-reading brokers. Host GPU
passthrough is unsupported.

Online mode preserves the same filesystem isolation and private network:

```json
{"mode":"https-relay","hosts":["api.openai.com"]}
```

Use exact operator-approved model API hostnames, no wildcard or URL, in the
policy's `network` field. The host relay accepts only HTTP CONNECT to these
names on TCP 443. Every DNS answer must be a global public, non-reserved,
non-multicast, non-mapped address; mixed public/private answers fail. It connects
to the validated numeric address without a second DNS lookup. Only the relay's
socket is mounted, at `/guard/relay.sock`. An in-sandbox forwarder exposes it as
`http://127.0.0.1:18080` and sets `HTTPS_PROXY`/`https_proxy`. Ignoring those
variables gives the agent no direct network path. Overriding them cannot widen
the host relay's fixed policy. No DNS service is exposed inside the namespace.

For a client that uses TLS, separately approve a real CA bundle as
`/inputs/certificates/ca-bundle.crt` (input ID `certificates`, relative path
`ca-bundle.crt`). For example, the operator can approve the regular system file
`/etc/ssl/certs/ca-certificates.crt` and its hash, using that source directory and
the filename `ca-certificates.crt`; to get the fixed sandbox filename instead,
prepare a **separate cleared copy** named `ca-bundle.crt` outside mixed source
trees. The fixed `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS` reference this path.
Clients must support HTTP CONNECT and verify TLS certificates themselves.
Do not disable certificate verification. Additional client-specific dependencies
belong in the curated runtime or individually approved inputs.

If needed, explicitly pass a model credential already present in the launcher's
environment:

```sh
.venv/bin/guard-run run --policy /absolute/project/run.policy.json \
  --credential OPENAI_API_KEY -- /opt/runtime/bin/agent
```

Here `/opt/runtime/bin/agent` stands for your prepared runtime's actual agent
entry point; add its runtime mount to the policy. Only `OPENAI_API_KEY` and
`ANTHROPIC_API_KEY` are supported opt-ins. There are no secret values in the
policy or launcher argv; credentials pass in a sealed memfd into the sandbox
and then into the command's environment. No other environment is inherited.
Use a project credential with appropriate provider limits. Never pass library,
Westlaw, Lexis, Nextcloud or desktop account credentials. Without `--credential`,
even those two environment variables are discarded.

**Network control is not exfiltration prevention or content clearance.** The
relay transports bytes without inspecting TLS, API paths, prompts, responses or
license status. It enforces endpoint and address policy, not the TLS protocol;
a client could send any TCP payload to an allowed endpoint's port 443. Cleared
inputs, outputs and deliberately passed model credentials can be transmitted
there. An approved endpoint must not be a remote file/tool broker or a host
service reachable through public/NAT addressing. It must not return licensed
library content. Public addressing alone does not establish clearance. Provider
behavior, retention, authentication, responses, remote tools and the relay's
host DNS resolver are outside filesystem enforcement. Do not enable this mode
when those assumptions cannot be established; use offline mode instead.

The host-side relay is part of the trusted computing base outside the sandbox.
Its only implemented operation is a validated CONNECT tunnel: no filesystem,
credential lookup, shell, redirect following or model-server API. Its code and
the kernel/Bubblewrap/runtime require independent review. The untrusted agent
can replace its in-sandbox forwarder, but the host policy still applies.

## Audit and acceptance evidence

Runner stderr consists of metadata-only JSON events: operation/status/exit code
or fixed refusal reason. It never includes source contents, hashes, filenames,
policy text, argv, environment, credentials, relay headers/payload or exception
text. Redirect that stream to a **host-side** decision log if wanted. The
configuration contains paths, clearance labels, digests and endpoint names,
never source text or secrets. Treat names/digests as potentially sensitive
metadata and keep the policy private.

Agent stdout/stderr are untrusted **output artifacts** at
`/out/agent.stdout` and `/out/agent.stderr`, not decision logs. The agent can
write any data it knows, including deliberately supplied credentials, to those
artifacts or other approved outputs. Do not publish them as safe audit logs.
The runner cannot prevent an agent from printing a secret it was explicitly
given. The existing secret scanner has its own documented behavior; it is not
used as an isolation substitute or included in these metadata logs.

```sh
# Require actual restricted-process tests; skipping is a failure.
GUARD_REQUIRE_ISOLATION=1 .venv/bin/python -m unittest discover -s tests -t . -v
```

Without that variable, unsupported-host integration tests explicitly skip;
ordinary scanner/gate tests passing is not evidence of source isolation. CI has
a separate Linux isolation job requiring actual execution. Tests use synthetic
files and synthetic DNS/echo fixtures only, with no licensed content, provider
credentials or external model calls. They demonstrate successful cleared reads,
failed licensed/unclassified reads, children and alternate paths, constrained
writes, policy/namespace tampering, FD/environment scrubbing, unavailable
prerequisites, digest changes, symlinks, hard links, nested bind mounts, network
denials and working approved transport. See [validation.md](validation.md).

## Threat model and limits

The adversary is the agent and all its descendants, including arbitrary native
code, subprocess tools and a local model started by it. On a successfully
probed host, kernel mount/process/network namespaces and read-only mounts prevent
their direct filesystem reads of host material not explicitly exposed. The
manifest also prevents unclassified additions within input roots from appearing.
An advisory DENY result is never used as proof of a failed filesystem operation.

Trusted: the operator and clearance decisions, launcher and installed package,
curated software/runtime, Bubblewrap, kernel, relay and host administrators.
A malicious same-user host process could change runtime files or inject data
into writable roots; it is outside this boundary. No protection against kernel
exploits, compromised trusted components, host root/debuggers, CPU side channels,
resource exhaustion, model memorization, or information intentionally supplied
by humans/approved remote services is claimed. File metadata is not fully hidden
(private procfs and mounted runtime metadata exist). Snapshots can consume memory
and setup time for large corpora/models; no cgroup quotas are installed.

Use a dedicated VM for stronger separation from hostile host processes. Starting
only a tool underneath `guard-run` leaves an agent running elsewhere outside the
boundary; launch the entire agent/server workflow underneath it. No changes to
the current desktop's providers, permissions, accounts or services are made.

Design references: [Bubblewrap's security model](https://github.com/containers/bubblewrap#sandbox-security)
and [kernel openat2 resolution semantics](https://man7.org/linux/man-pages/man2/openat2.2.html).
