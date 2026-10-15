# Security

fourneau faces the internet alone, so a flaw in it is a flaw in every server built on it. Report
one by a private security advisory on GitHub, not an issue.


## What a deployment holds

Only its certificate's private key, either in files the operator gives (theirs to keep and rotate),
or by ACME in a state directory the program names: the account key, the certificate's key and its
chain, each mode 0600, written whole and renamed into place. A restart that finds the certificate
with a third of its life left orders a new one, with a new key. After the handshake the session
keys are the kernel's (kTLS).
