# Security policy

## What this is

Aragami is a read-only static posture auditor for Tor Browser and Firefox. It reads files and
reports what it finds. It never launches the application under audit, and it never touches the
network except for the version lookup. Every response carries a boundary notice, error paths
included.

## What counts as a security issue here

The interesting category for a tool like this is not a crash. It is being **wrong**.

- **A false negative.** The audit examined a profile that retains state and reported nothing.
  This is the failure that matters most: the tool exists to point at residue, so failing to
  point at residue is the defect. A gap in coverage that is *documented* is a boundary; a gap
  that is not is a bug, and reports of the second kind are wanted.
- **An unfounded claim.** Any output that reads as a safety assertion, or any path that returns
  a result without the boundary notice. The rule the code is held to is that the auditor states
  what it observed, never what the observation implies about safety.
- **A write, or a launch.** Anything that modifies a file under audit, creates one, or starts a
  browser. The tool is read-only by construction, so a path that is not is a defect.
- **Network access beyond the version lookup.** The tool is expected to be usable with no
  network at all. Anything else has to be deliberate and visible.
- **Disclosure of the user's own data.** Profile paths, account names, saved-login metadata or
  bridge lines appearing anywhere other than the local result the caller asked for -- including
  in an error message, an exception, or a log.
- **A seal that opens with something other than its source work.** `Aragami` carries a sealed
  statement, described in the README. A seal that opens for the wrong input, or a tampered seal
  that opens at all, contradicts what that file claims.
- **A pinned action whose SHA does not match its version comment**, which is the one place a
  supply-chain change could enter the release pipeline unnoticed.

## What is not one

- **The postures the tool reports.** Findings about a browser's configuration are the tool
  working, not a vulnerability in it.
- **The layers the tool says it does not cover.** Traffic correlation, endpoint compromise, and
  what happens after decryption are outside a static auditor by definition. The boundary notice
  states this on every response; it is not an oversight.
- **A clean audit of an unsafe setup.** "A clean audit is NOT proof of safety" is the first
  thing the tool says about itself, and treating a clean result as a guarantee is a misuse of
  the tool rather than a defect in it. The distinction from the false negative above is what
  the tool *could* have observed: residue it had the means to detect and did not is a bug;
  a layer it never claimed to reach is not.

## Reporting

Open a private advisory:

    https://github.com/Nesarf/Aragami/security/advisories/new

Private vulnerability reporting is enabled on this repository, so a report stays between the
reporter and the maintainer until an advisory is published. Please do not open a public issue
for anything in the first list.

## What to expect

This is a single-maintainer project. There is no response-time commitment, because one would
not be kept, and a policy that is not honoured is worse than no policy at all. Reports are
read. If a report leads to a change, an advisory is published and the reporter is credited
unless they would rather not be.

## Supported versions

The latest release, and `main`. Older versions are not maintained.

## Scope

This policy covers the tool: its code, its packaging, its release pipeline, and its published
artifacts. It does not cover the browsers it audits, or the configurations it reports on.
