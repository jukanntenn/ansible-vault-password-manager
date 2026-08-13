---
name: commit
description: Use when the user asks to commit changes.
---

# Commit

Group by logical change, not by file. Draft a plan, confirm, then execute.

1. Check current changes and recent commit style.
2. Present the plan once; commit batch by batch on confirmation; stop if rejected.
3. prek runs automatically; never `--no-verify`.
4. Single file → skip the plan, commit directly.

Message: Follow Conventional Commits.

- Never silently include unrecognized files.
- Never push.
