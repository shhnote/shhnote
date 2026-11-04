## How we protect your secrets

- **Encrypted in your browser.** Your note and files are encrypted on your device before they are uploaded. The key is only in your link, so we never have it.
- **Gone when you say so.** Secrets are deleted when they expire. With burn after reading, the first opening uses the secret up: nobody else can fetch it, and it is deleted once the recipient's browser has decrypted it, or when the short re-download window ends.
- **Optional passphrase.** Add one for a second layer of protection, so a leaked link alone isn't enough.
- **Strict browser protections.** Our pages only load code from our own server, can't be embedded in other sites, and never tell other sites where you came from.

## What we can't promise

- **Memory in your browser.** After a secret is shown, the page overwrites what it can when you leave. JavaScript can't guarantee that, so your browser may keep decrypted data in memory until the tab is closed. Close the tab when you're done.
- **Automated clicks.** The reveal page sends nothing about the secret until a real click or key press (only the page's own scripts and the Argon2 module are loaded, from this site, with no identifier in the request). A link scanner or browser extension that injects real input, as a person would, can open a single-view secret. The recipient then gets the same "no secret found" answer as for any used or expired link. It does not say why, but a link that should have worked and doesn't is the sign that something else read it.
- **Leftovers after deletion.** Deleting a secret removes the record. Encrypted leftovers may linger in database journals, free disk space or backups until they are overwritten. They are ciphertext without a key.
- **Timestamps on large files.** Large secrets stored outside the database carry the time the file was written, which the storage system records on its own.

## Tips for sharing safely

- Send the passphrase a different way from the link, for example the link by email and the passphrase by phone.
- Pick the shortest expiry that works for you.
- Use burn after reading for passwords and other one-time information.

## Reporting a vulnerability

If you think you've found a security problem, please email {{security_email}} and tell us privately before telling anyone else. Include what you found and how to reproduce it.

We will:

- reply within [number] working days;
- keep you updated while we fix it;
- credit you when we publish the fix, if you'd like.

Please don't access other people's data, disrupt the service, or run automated scans that put heavy load on it while testing.

Vulnerabilities in the shhnote software itself: see its [security policy]({{security_policy_url}}).
