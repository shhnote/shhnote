## How we protect your secrets

- **Encrypted in your browser.** Your note and files are encrypted on your device before they are uploaded. The key is only in your link, so we never have it.
- **Gone when you say so.** Secrets are deleted when they expire, or as soon as they're opened if you choose burn after reading.
- **Optional passphrase.** Add one for a second layer of protection, so a leaked link alone isn't enough.
- **Strict browser protections.** Our pages only load code from our own server, can't be embedded in other sites, and never tell other sites where you came from.

## What we can't promise

- **Memory in your browser.** After a secret is shown, the page overwrites what it can when you leave. JavaScript can't guarantee that, so your browser may keep decrypted data in memory until the tab is closed. Close the tab when you're done.
- **Automated clicks.** The reveal page fetches nothing until a real click or key press. A link scanner or browser extension that injects real input, as a person would, can open a single-view secret. The recipient then sees that it was already opened, which is the honest outcome: something else read it.
- **Leftovers after deletion.** Deleting a secret removes the record. Encrypted leftovers may linger in database journals, free disk space or backups until they are overwritten. They are ciphertext without a key.
- **Timestamps on large files.** Large secrets stored outside the database carry the time the file was written, which the storage system records on its own.

## Tips for sharing safely

- Send the passphrase a different way from the link, for example the link by email and the passphrase by phone.
- Pick the shortest expiry that works for you.
- Use burn after reading for passwords and other one-time information.

## Reporting a vulnerability

If you think you've found a security problem, please email [security email] and tell us privately before telling anyone else. Include what you found and how to reproduce it.

We will:

- reply within [number] working days;
- keep you updated while we fix it;
- credit you when we publish the fix, if you'd like.

Please don't access other people's data, disrupt the service, or run automated scans that put heavy load on it while testing.
