# Contributing to lanpair

Thanks for helping. Bug reports, ideas and pull requests are all welcome. Please follow the
[code of conduct](CODE_OF_CONDUCT.md); security problems go to [SECURITY.md](SECURITY.md).

lanpair is a security library: other projects trust it to decide which messages are real.
Changes are reviewed with that in mind, so please explain the security impact of anything that
touches keys, signatures, pairing or what is accepted from the network.

## Reporting a problem

Open an [issue](https://github.com/TonyD365/lanpair/issues/new/choose) and fill in the form. The
version, your Python version and system, and a short code sample make a problem much quicker
to find.

## Setting up

You need Python 3.10 or newer.

```bash
git clone https://github.com/TonyD365/lanpair.git
cd lanpair
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The design and threat model are in [docs/design.md](docs/design.md). Read it before changing
the protocol.

## Issues

The bot labels a new issue by what it is about (area and system), and asks for the version and
system when a bug report has none (`needs-info`, gone once they are added). When a pull request
that says `Fixes #12` is merged, #12 hears about it (`fixed-in-next-release`), and again with the
version once that is released. In an issue, start a comment
with `@TonyD365-Agent`, then `/close` or `/reopen` (whoever opened it, or a maintainer), `/label`
or `/unlabel` (maintainers), or `/help`. They work as on pull requests.

## Before you open a pull request

```bash
ruff check . && ruff format --check .
mypy src
pytest
```

CI runs the same checks on macOS, Windows and Linux.

### The checks on a pull request

**Commands:** start a comment with `@TonyD365-Agent`, then the command, for example
`@TonyD365-Agent /retest`. The bot ignores comments that do not start with the mention.

- `/retest` re-runs the checks that failed or were cancelled; `/ready` marks a draft ready for
  review; `/close` and `/reopen`; `/update` merges `main` into your branch (you or a
  maintainer; on a fork, a maintainer).
- After merging, the bot deletes the pull request's branch (not a fork's). `/keep-branch`
  keeps it and `/delete-branch` undoes that (you or a maintainer).
- `/remind 3d` (or `12h`, up to `30d`, optionally with a note) has the bot remind you there then.
- `/label` and `/unlabel` add or remove labels (maintainers: the owner and collaborators).
- `/help` lists them.

A pull request that waits on its author (`Needs-Author-Action`) with no push or comment from
them for 30 days gets the `Stale` label and a reminder, and is closed after 30 more days. It
can always be reopened.

A bot keeps one comment on each pull request up to date: which checks passed or failed, what a
failure usually means, and what happens next. Besides the tests on three systems and the lint:

- **Security** audits the Python dependencies and runs CodeQL on the code and the workflows;
  **zizmor** checks changes to the workflows.
- **Labels** are added from the files you change (`crypto`, `discovery`, `keystore`, ...).
- A pull request needs the maintainer's approval, and every check passing, before it is merged.
  The bot sums the checks up in one status, **lanpair checks**; once the maintainer approves, it
  merges the pull request as soon as that status is green (at once if it already is).
- The bot also keeps **status labels** up to date: `Checks-Running`, `Checks-Passed`,
  `Checks-Failed`, `Internal-Error` (a check was cancelled or timed out, usually not the
  change's fault), `Merge-Conflict` (bring `main` into your branch, resolve, push; nothing is
  merged until then), `Needs-Author-Action`, `Changes-Requested` (the maintainer's review asks
  for changes), `Needs-Terms-Agreement`, `Needs-Review` and `Maintainer-Approved`.
  `Keep-Branch` (from `/keep-branch`) is yours to set: the bot never removes it. When the
  status changes it posts a new comment, so the newest status is always the latest comment.

A few conventions:

- Everything a user or a contributor reads is in English: the API, docs, comments, commit
  messages and pull requests.
- Secure by default: an API that can be misused into accepting a forged or replayed message
  needs a very good reason. Rejected input never reaches application code.
- Never put key material in logs, `repr`, exception messages or plain files.
- Use well-reviewed primitives (`cryptography`); do not implement cryptography by hand. The one
  protocol built on them here, CPace (`cpace.py`), follows its published specification and is
  tested against its official test vectors; any change to it needs the same.
- Tests must not need the network. Every check that rejects a message has a test that shows it
  being rejected.
- New behaviour comes with tests in the same pull request, and a fixed bug with a test that
  fails without the fix.
- One topic per pull request, with a description of how you checked it.

## Contribution terms

On your first pull request the bot posts these terms as a comment. Reply with a comment that
says exactly

    @TonyD365-Agent I agree to the lanpair contribution terms

and the check called **Contribution terms** turns green (it stays red until then). By replying
you agree that:

1. **License.** Your contribution is released under the [MIT License](LICENSE), like the rest
   of lanpair.
2. **It is yours to give.** You wrote it, or you have the right to contribute it under that
   license. Code from elsewhere is marked, with its source and license, and that license allows
   this.
3. **It may be changed or declined.** The maintainer may edit, rearrange or decline a
   contribution, and you are credited in the project's history (git), not paid.
4. **No warranty.** You give it as is, like the rest of lanpair.
5. **Conduct.** You follow the [code of conduct](CODE_OF_CONDUCT.md).

The maintainer and the project's bots are not asked. Your answer is recorded (in an issue the
bot keeps), so once you have agreed, your later pull requests count as agreed too, until you
withdraw by replying `@TonyD365-Agent I do not agree to the lanpair contribution terms`. A pull request whose
author has not agreed is labelled `Needs-Terms-Agreement`, and `Terms-Declined` after a no.
