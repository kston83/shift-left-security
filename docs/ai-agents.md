# AI coding agents

AI coding agents (Claude Code, Copilot agent mode, Cursor, Codex, ...) edit files and run
`git commit` like any developer. Git hooks run no matter who or what makes the commit, which
makes them one of the few guardrails that apply consistently to agent-written code.

## What slsec adds

* **Secrets in agent config.** MCP server configs often end up with tokens pasted inline,
  and they're easy to commit by accident. The slsec gitleaks policy adds rules for:
  * `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`
  * `.claude/settings.json`, `.claude/settings.local.json`, `claude_desktop_config.json`
  * `.gemini/settings.json`

  It flags any `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*` or `Authorization` value that is a
  literal rather than an environment reference.

  ```jsonc
  // flagged
  "env": { "JIRA_API_TOKEN": "ATATT3xFfGF0..." }
  // fine: resolved from the environment at runtime
  "env": { "JIRA_API_TOKEN": "${JIRA_API_TOKEN}" }
  ```

* **AI provider keys.** The default gitleaks rules already detect Anthropic, OpenAI, Hugging
  Face and similar keys in any file.

## Recommendations

* Keep personal agent settings out of git: add `.claude/settings.local.json` and similar
  files to `.gitignore`.
* Don't let agents bypass hooks. Deny `git commit --no-verify` and `git push --no-verify` in
  the agent's permission settings. CI catches it anyway, but later.
* Treat agent-generated IaC like any other change: `slsec-checkov` in `mode: block` is a
  reasonable default for repos where agents write Terraform.
