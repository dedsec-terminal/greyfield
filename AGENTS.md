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
