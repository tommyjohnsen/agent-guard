<!--
PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
written-by: codex/gpt-6 | 2026-11-13 | :/isolate-capstone-sources-v1
modified-by: codex/gpt-6 | 2026-11-13 | :/setup-bind-mount-fixture-v2
reviews: pending current exact-commit claude-code and grok-build approval
END PROVENANCE
-->
# Linux source isolation validation

Executed 2026-11-13 against upstream base
`195cdd73eb45f55e78ff5024da614ab0dfbe3702` plus this branch's implementation.
Host: Linux 6.8.0-147-generic, x86-64; Python 3.12.3; Bubblewrap 0.9.0;
non-root execution. All fixtures are synthetic.

```sh
GUARD_REQUIRE_ISOLATION=1 python3 -m unittest discover -s tests -t . -v
```

Result: **394 tests passed, zero skipped**. This includes 373 upstream tests
and 21 new runner/relay tests. Real namespace tests were run outside the
development tool's own sandbox, which otherwise prevents the required namespace
setup. That restriction was not bypassed or silently downgraded by `guard-run`.

| Evidence | Observed result |
| --- | --- |
| Digest-cleared PUBLIC/ALT and NOTES files | Real `read_bytes()` succeeds with expected bytes |
| Existing synthetic LICENSED and unclassified host files | Real `os.open()` raises `OSError` |
| New unlisted file inside cleared input root | Real open fails |
| Independently exec'd Python children | Forbidden opens exit nonzero |
| Traversal, `/proc/1/root`, `/proc/self/root`, output symlink | Forbidden opens fail |
| Forbidden hard-link creation | Actual `os.link()` fails |
| Symlink/hard-link/FIFO inputs and changed digests | Runner exits 125 before launching the agent |
| Nested bind mount created in disposable user/mount namespace | `openat2` refuses to cross it |
| `/out`, `/cache`, `/tmp` | Written files visible only in approved host directories |
| Writes to `/`, `/usr`, `/inputs`, `/guard` | Real write opens fail |
| Policy overwrite and fake policy/environment in output directory | Host policy unchanged; descendant read still fails |
| Mount, user-namespace and setns attempts | Actual syscalls fail |
| Inherited source FD and host environment | Agent has no setup/source FD above 2; environment scrubbed |
| Existing host TCP and Unix services | Actual connect attempts fail inside restricted child |
| Unusable runtime / absent Bubblewrap / unsupported platform | Clear failure; no agent output is created |
| Online namespace | Forbidden host-source read remains blocked |
| Allowlisted relay transport | Real restricted child exchanges synthetic bytes through CONNECT |
| Unlisted endpoint, wrong port, private/mixed/mapped/multicast DNS answers | Relay refuses without forwarding payload |
| Source/credential/payload sentinels | Absent from runner audit and relay logs |

The successful relay round-trip uses a local synthetic echo fixture with the
test resolver explicitly replaced. Separate production-resolver tests prove
that loopback/private addresses are rejected. No external provider call or real
credential was used. The test does not establish remote provider behavior or TLS
client correctness.

A clean temporary virtual environment also successfully built and installed the
package. Its `guard-run` console command ran the documented synthetic preflight
and launch:

```text
{"event": "check", "status": "enforceable", "code": 0}
{"event": "run", "status": "exited", "code": 0}
```

The approved output contained the expected synthetic input. Byte compilation
and `git diff --check` also passed. No real research trees were inspected or
modified. CI is configured to require real isolation rather than silently skip
it; a future CI run is separate evidence from these local results.

The initial Ubuntu CI run exposed a test-fixture portability issue: raw
`unshare` UID mapping was blocked by AppArmor even though the production
Bubblewrap sandbox worked. AppArmor also denied a helper's mount syscall.
The fixture now asks Bubblewrap to create the synthetic nested bind mount during
setup, then tests resolution with all capabilities dropped. The production
runner's capability drop and disabled user namespaces remain in effect.
No AppArmor, sysctl or desktop settings were changed to run the tests.

This is implementation/test evidence, **not an independent security review**.
No self-review verdict is issued. Current exact-commit APPROVE reviews from both
`claude-code` and `grok-build` remain required before merging or releasing.
