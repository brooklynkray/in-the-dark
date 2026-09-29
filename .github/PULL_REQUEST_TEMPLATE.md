## What this changes

Briefly, what and why.

## Testing

- [ ] `python3 -m pytest` passes locally
- How you tested it (and, if behavioural, whether you ran it in an authorised lab)

## Security

If this touches command execution, input handling, privilege or file writes:

- [ ] Commands are argument lists run with `shell=False`; no user input in a command string
- [ ] Any new tool option is a fixed, allow-listed flag, not free text
- [ ] New input (targets, ports, filenames) is validated at the boundary
- [ ] External tool output is parsed defensively as untrusted data
- [ ] No new elevation; parsing and saving still run unprivileged
- [ ] Result file names are generated, not built from the target

## Checklist

- [ ] One focused change on a `feat/`, `fix/` or `docs/` branch
- [ ] Commit messages say what and why
