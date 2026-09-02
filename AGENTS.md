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
  - Fan out aggressively: whenever 2 or more files are involved, spawn parallel Antigravity subagents concurrently.
  - Keep Codex context lean: return only concise 3-line summaries (`### Files Changed`, `### Verification`).

## Performance & Windows Tooling Rules
- **DO NOT USE `grep_search`**: On Windows, the native `grep_search` tool has a known bug parsing drive letters (`D:\...` fails with `strconv.Atoi`).
  - Instead of `grep_search`, ALWAYS use `view_file` to inspect files directly.
  - If searching across files is required, run `rg` via `run_command`.
- **Targeted Fast Execution**:
  - Open the requested dashboard files immediately with `view_file`.
  - Apply edits with `replace_file_content`.
  - Run syntax checks (`node -c <file>`) via `run_command` and return promptly.
  - **No Browser Automation**: Do not launch Chrome, Lighthouse, or browser tests during code editing passes.
  - Return a concise summary (`### Files Changed`, `### Verification`) in under 30 seconds.
