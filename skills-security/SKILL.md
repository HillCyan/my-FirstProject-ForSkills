---
name: "skills-security"
description: "Performs local security-first assessment for Skills. Invoke when users request security audit, risk ranking, or batch scan for Trae/OpenClaw/cc/Cursor skills."
---

# Skills Security

## Purpose

Run local, reproducible security assessment for Skill directories and output actionable risk findings.

## When To Use

- User asks for Skill security review
- User asks to rank high-risk skills
- User asks to batch scan a skills repository
- User asks to audit newly added skills periodically

## Security Focus

- Dangerous command patterns
- Hardcoded secret patterns
- Shell execution and privilege-escalation signals
- Side-effect and rollback risk signals

## Typical Usage

1. Confirm target skills root directory.
2. Execute local scan tooling.
3. Collect high-risk findings and evidence paths.
4. Output prioritized remediation actions.
