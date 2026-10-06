# Security

fourneau is meant to face the internet alone, so a flaw in it is a flaw
in every server built on it.

## Reporting

A security problem in fourneau: open a private security advisory on
GitHub (Security, Report a vulnerability), not an issue.

## What it holds

No secrets. Once TLS and ACME land (M7, M8), a deployment holds its
certificate's private key and its ACME account key on its own disk; how
they are stored will be written here then.
