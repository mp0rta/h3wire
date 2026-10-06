# Publishing h3wire

Publishing is manual. Merge the release commit into `main` before publishing;
this workflow never uploads from another branch or repository and never creates
a tag. The maintainer creates and merges the PR and configures external settings.

## One-time setup

1. In `mp0rta/h3wire` GitHub settings, create the **release** Environment.
   Configure required reviewers and select **main** as its only deployment
   branch. A sole maintainer must allow self-review to avoid blocking releases.
   Confirm these protection rules are available for the repository's GitHub plan.
2. Publish the initial version locally: crates.io Trusted Publishing currently
   requires the crate to exist first. Create an API token with only the
   **publish-new** scope and the exact crate name pattern **h3wire**;
   **publish-update** is not needed for this first upload. Choose the shortest
   suitable expiry (the 7-day preset or a custom expiry), run `cargo login`
   locally, then run
   `cargo publish -p h3wire --locked` from the reviewed release commit after all
   verification gates below pass. Never put the token in chat or GitHub secrets.
3. On the crate's crates.io settings page, register this Trusted Publisher:

   | Field | Value |
   | --- | --- |
   | GitHub owner | `mp0rta` |
   | Repository | `h3wire` |
   | Workflow filename | `publish.yml` |
   | GitHub Environment | `release` |

4. Enable **Trusted Publishing Only** after registration. Revoke the bootstrap
   API token specifically and run `cargo logout` locally to remove its saved
   credential. Future releases use temporary OIDC credentials.

See the official [Trusted Publishing documentation](https://crates.io/docs/trusted-publishing)
and [authentication action](https://github.com/rust-lang/crates-io-auth-action).

## Each release

1. Update the crate version and lockfile as needed, review the release diff, and
   merge the release commit into `main`.
2. In GitHub Actions, select **Publish to crates.io**, choose **main**, and run
   the workflow. Review the run's exact commit SHA before approving the
   **release** Environment deployment.
3. The verification job checks formatting, Clippy, workspace tests, warning-free
   docs, the Rust 1.85 build, packaging, extracted-package tests, and a publish
   dry run. It has no OIDC permission. The publish job checks out the same SHA,
   authenticates immediately before upload, and exposes the temporary registry
   token only to `cargo publish`. The authentication action revokes it at job end.
4. After success, confirm the expected version on crates.io and docs.rs, and
   build/test a fresh consumer using the published registry version. Only then
   create the version tag on the exact commit SHA from the successful run.

Tags do not trigger publication. Do not retry a completed upload with the same
version; crates.io versions are immutable. Review and update the pinned Action
SHAs when upgrading Actions.
