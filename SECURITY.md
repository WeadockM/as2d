# Security policy

as2d handles private keys, partner certificates and business documents, so
security problems are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Report it
privately through GitHub instead: on the repository's **Security** tab,
choose **Report a vulnerability**. Include what you found, how to reproduce
it, and which version you tested (`as2d -version`).

You should get a first response within a few days. Once a fix is ready, it
will be released and the advisory published, crediting you unless you prefer
otherwise.

## Supported versions

as2d is pre-1.0. Security fixes go into the latest release only, so please
stay on the most recent version.

## Scope

In scope: anything that lets an attacker read, forge or alter messages, get
past signature, encryption or MDN checks, reach files or data they should not
(including through the dashboard or API), or run code on the host.

Deployment choices that the documentation warns against are out of scope,
for example exposing the API without `api_token`, or serving it over plain
HTTP on a network.
