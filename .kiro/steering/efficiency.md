# Efficiency Rules

Apply these to every task automatically — do not wait for them to be restated.

- Edit only the files named in the prompt. Do not read or refactor others.
- Run only the tests for the changed area, plus the full suite once at the very end.
- Do not create scratch files in the repo; use the system temp folder.
- Do not write explanatory reports. Final reply: max 8 lines (files changed, tests run, anything not done).
- Before reporting done, run `python -m pyflakes` on the files you changed and fix any findings.
