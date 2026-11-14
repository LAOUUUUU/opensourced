# Contributing

Barely-free is run by one person. Thank you for reading the code.

## How this repository works

The public repository, `LAOUUUUU/opensourced`, is a scrubbed copy of a private one, published at releases. Server addresses and private notes are replaced or left out, and each published copy is one commit, without the private repository's history. So:

- Issues are read. Use them for bugs in the code, mistakes in the docs, or ideas.
- Pull requests are read too, but they are not merged here: a change that is taken is made in the private repository and arrives in the next published copy, with credit in its commit message if you want it.
- Questions about using the VPN belong on the website's help page, <https://barely-free.com/help>.

## Security problems

Never in a public issue or pull request. See [SECURITY.md](SECURITY.md) for the private form and the rules.

## If you change the code

- Rust, formatted with `cargo fmt`, and clean under `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo test --workspace` passes. Behaviour changes come with a test that fails without them.
- The website runs no scripts and loads nothing from other sites; changes must keep that (the tests check it).
- Explain what changed and why in plain words.

By sending a change you agree that it is published under this repository's MIT licence.
