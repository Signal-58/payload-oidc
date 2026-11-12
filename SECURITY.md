# Security

This package decides who can sign in to a CMS, so we treat any flaw in it as serious.

## Reporting a vulnerability

Report it privately through GitHub: on this repository, open **Security**, then **Report a
vulnerability**. Please don't open a public issue, pull request or discussion for it.

Include the version, your Payload version, how to reproduce it, and what an attacker gains. We
aim to acknowledge a report within three working days and to agree a disclosure date with you once
we know the fix.

## Supported versions

Only the latest release gets fixes. A fix is released as a new version from this repository, with
npm provenance, and noted in [CHANGELOG.md](CHANGELOG.md).

## Scope

In scope: the plugin's sign-in flow, session handling, password refusals, reconcile, removal, and
its endpoints. Out of scope: vulnerabilities in Payload, `openid-client` or the identity provider
themselves (report those upstream), and setups that ignore the README, for example an app that
replaces the plugin's field access after plugins run, or a provider that lets users change their
own email without marking it unverified.
