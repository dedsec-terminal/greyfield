# Greyfield agent guidance

- Treat this repository as defensive honeypot infrastructure.
- Preserve the staged deployment gates in `docs/RUNBOOK.md`.
- Never place private keys, captured malware, raw Cowrie logs, or cloud secrets
  in the repository.
- Keep real SSH on `2223`; keep Cowrie SSH/Telnet on `2222`/`2323` behind NAT
  redirects from public ports `22`/`23`.
- The supported baseline is Ubuntu 22.04 x86-64 and Cowrie 3.0.13.
- Validate shell scripts with `bash -n scripts/*.sh` and ShellCheck before
  changing deployment behavior.
- Do not commit or push unless the user explicitly requests it.

## Prime Objective: Aggressive Codex Token Preservation
- **Codex Tokens Are Precious; Antigravity Tokens Are Abundant**:
  - Never write large diffs or whole files inside Codex. Always offload code generation and file edits to Antigravity.
  - Fan out aggressively: whenever $\ge 2$ files are involved, spawn parallel Antigravity subagents concurrently.
  - Sub-25s Single-Yield: Calibrate tasks to return under 25s so Codex's 30s poll resolves on the very first yield.
  - Pre-flight Port Probing: Probe ports before browser calls (`Test-NetConnection -Port <port>`).
  - Offload Benchmarks: Delegate local server + Lighthouse testing to Antigravity.
  - Keep Codex context lean: return only concise 3-line summaries (`### Files Changed`, `### Verification`).

## Performance & Windows Tooling Rules
- **DO NOT USE `grep_search`**: On Windows, the native `grep_search` tool has a known bug parsing drive letters (`D:\...` fails with `strconv.Atoi`).
  - Instead of `grep_search`, ALWAYS use `view_file` to inspect files directly.
  - If searching across files is required, run `rg` via `run_command`.
- **Worktree & Port Isolation**: When operating in massive swarms ($\ge 4$ subagents), run inside isolated worktrees (`..\worktrees\worker-N`) and bind to sharded ports (`8801+`).
- **Targeted Fast Execution**:
  - Open the requested dashboard files immediately with `view_file`.
  - Apply edits with `replace_file_content`.
  - Run syntax checks (`node -c <file>`) via `run_command` and return promptly in under 25 seconds.
  - Return a concise summary (`### Files Changed`, `### Verification`).
