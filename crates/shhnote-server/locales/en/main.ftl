-brand = shhnote

## Layout

brand-name = { -brand }
language-name = English
skip-to-content = Skip to content
nav-label = Main
nav-home = New secret
nav-how-it-works = How it works
nav-about = About
nav-contact = Contact
nav-language = Language
nav-theme = Theme
theme-auto = Match system
theme-light = Light
theme-dark = Dark
theme-light-hc = Light, high contrast
theme-dark-hc = Dark, high contrast
footer-tagline = Open-source, end-to-end encrypted, zero-knowledge secret sharing. Text and files. The server never sees your data.
footer-product = Product
footer-legal = Legal
footer-settings = Settings
footer-source = Source code
footer-project = Project
footer-notice = No cookies · No tracking · No external requests
page-terms = Terms of service
page-privacy = Privacy policy
page-security = Security
page-acceptable-use = Acceptable use
page-docs = API documentation

## Home

home-title = Share secrets securely with self-destructing links
home-intro = Keep passwords, keys and files out of chat logs, email threads and ticket histories. Everything is encrypted in your browser before it leaves your device.
noscript-create = JavaScript is needed to encrypt your secret in your browser. Please turn it on to create a secret.
form-note-label = Your secret
form-note-placeholder = Enter your message here…
form-files-label = Files
form-files-drop = Drop files here
form-files-click = or click to attach
form-files-hint = Encrypted in your browser before upload · up to { $size } in total
form-files-remove = Remove
form-expiry-label = Expires in
expiry-15m = 15 minutes
expiry-30m = 30 minutes
expiry-1h = 1 hour
expiry-6h = 6 hours
expiry-12h = 12 hours
expiry-1d = 1 day
expiry-3d = 3 days
expiry-7d = 7 days
expiry-14d = 14 days
form-burn-label = Burn after reading
form-burn-hint = Delete the secret as soon as it has been opened once. Otherwise it can be opened until it expires.
form-passphrase-label = Passphrase
form-passphrase-optional = (optional)
form-passphrase-hint = A second lock. The recipient will need it; send it over a different channel than the link.
form-passphrase-toggle = Show or hide the passphrase
form-disclaimer = By creating or opening a secret you agree to our
form-submit = Encrypt secret
chips-label = Guarantees
chip-e2ee = End-to-end encrypted
chip-zero-knowledge = Zero knowledge
chip-no-logs = No logs
chip-open-source = Open source
chip-no-account = No account needed

## Create result

result-eyebrow = Link ready
result-title = Send it, then forget it.
result-intro = Copy the link and share it however you like. It won't be shown again once you leave this page.
result-share-label = Share link
result-chips-label = Secret settings
result-chip-single = Single view
result-chip-multi = Open until it expires
result-chip-expires = Expires in { "{period}" }
result-callout = Anyone with the full link can open the secret. If you set a passphrase, send it over a different channel than the link itself.
result-passphrase-reminder = You set a passphrase. The recipient needs it as well as the link.
result-private-divider = private controls · keep to yourself
result-burn-label = Burn link
result-burn-sub = destroy it yourself, anytime
result-burn-hint = Save this somewhere private. Opening it and confirming destroys the secret before anyone can view it. If you lose it, it can't be recovered.
result-copy = Copy
result-copied = Copied
result-open = Open the link
result-destroy = Destroy now
result-destroyed = Destroyed. The secret is gone from the server.
result-another = Create another secret
create-encrypting = Encrypting in your browser…
create-uploading = Uploading…
create-error-empty = Add some text or at least one file.
create-error-too-large = That's more than this site accepts. Remove some files or shorten the text.
create-error-network = Couldn't reach the server. Check your connection and try again.
create-error-failed = Something went wrong while creating the secret. Please try again.
create-error-wasm = Passphrases need WebAssembly, which your browser or its security level has switched off. Allow it, or create the secret without a passphrase.

## Reveal

secret-title = Someone shared a secret with you
secret-intro = It's decrypted in your browser. If it was sent as a single view, it's deleted the moment you open it, so reveal it only when you're ready to read and save it.
noscript-page = This page needs JavaScript to do anything. Please turn it on.
noscript-view = JavaScript is needed to decrypt this secret in your browser. Please turn it on to view the secret.
secret-reveal = Reveal secret
secret-passphrase-note = If the sender set a passphrase, you'll be asked for it after you press the button.
reveal-armed-badge = Nothing fetched yet
reveal-callout = Nothing has been fetched: this is all an automated scanner sees. The reveal is manual on purpose, so email security, chat previews and antivirus can't open your secret before you do.
reveal-working-badge = Working
reveal-fetching = Fetching the encrypted secret…
reveal-decrypting = Decrypting in your browser…
reveal-passphrase-badge = Locked
reveal-passphrase-title = This secret needs a passphrase
reveal-passphrase-intro = The sender added a second lock. Retries happen in your browser; nothing is sent to the server.
reveal-passphrase-label = Passphrase
reveal-passphrase-submit = Unlock
reveal-wrong-passphrase = That passphrase didn't work. Try again.
reveal-revealed-title = Here it is. Save what you need now.
reveal-revealed-intro = This secret was decrypted in your browser.
reveal-single-view = Destroyed · this was the only view
reveal-output-label = secret · decrypted locally
reveal-copy-text = Copy
reveal-download = Download
reveal-close-warning = Handle it carefully. Once you leave this page there is no way to retrieve it again, from you or from us.
reveal-create-own = Create your own secret
reveal-not-found-badge = No secret found
reveal-not-found-title = No secret found here.
reveal-not-found-body = This link is invalid, or the secret it pointed to has already been viewed, expired, or been destroyed. For your privacy, this site keeps no record of which.
reveal-not-found-callout = If you still need the secret, ask the sender for a fresh link, and double-check you copied the whole URL, including the part after the #.
reveal-error-network = Couldn't reach the server. Try again in a moment.
reveal-error-corrupt = This secret couldn't be decrypted. The link may be incomplete.
reveal-error-wasm = This passphrase needs WebAssembly, which your browser or its security level has switched off (Tor Browser at "Safer", for example). Allow it and try again.

## Burn

burn-title = Destroy this secret
burn-badge = Armed · nothing happened yet
burn-intro = This is a burn link. Nothing has happened yet. Confirming deletes the secret permanently, before anyone can open it.
burn-confirm = Destroy the secret
burn-working = Destroying…
burn-done-badge = Burned · secret destroyed
burn-done-title = The secret has been destroyed.
burn-done-body = It's gone from the server. Nothing about it is kept.
burn-done-callout = Anyone who opens the share link from now on is simply told that no secret was found, with no way to tell whether it was viewed, expired or burned.
burn-not-found-badge = Nothing to destroy
burn-not-found-title = Nothing to destroy
burn-not-found-body = This burn link is invalid, or the secret was already viewed, expired, or destroyed.

## How it works

how-eyebrow = How it works
how-title = Send a secret that opens once, then vanishes
how-intro = No accounts, no apps, no jargon: three steps, and the full protocol is public for anyone who wants every detail.
how-s-1-title = You write your secret
how-s-1-body = Type a message or attach files: a password, a private note, a document. Before it leaves your device, your browser locks it in a sealed box that only a special key can open.
how-s-2-title = You get one link to share
how-s-2-body = This site hands you a single link with the key hidden inside it, after the #. Send that link however you like. The key travels with the link, never through this site's server, so nobody here can peek inside the box.
how-s-3-title = They open it, then it's gone
how-s-3-body = The recipient presses a button, their browser unlocks the box, and the secret is deleted from this site's server, right away for a single-view secret, or when the timer runs out.
how-s-callout-lead = Think of it like a note that burns after one reader.
how-s-callout = You seal it, hand it off, and once it's been read, it's gone. Even we, the people who run this site, can never read what's inside or bring it back.

how-cta-button = Create a secret
how-spec = Every primitive, parameter and trust boundary is written down in the protocol specification, with conformance vectors any implementation can check itself against.
how-spec-link = Read the specification

## About

about-title = About { -brand }
about-lead = { -brand } is a simple way to send passwords, notes and files that shouldn't stay around.
about-body-1 = Sensitive things often end up in chat histories and email inboxes, where they stay for years. { -brand } gives you a link that works for a limited time, or only once, and then the secret is gone for good.
about-body-2 = { -brand } is built so that whoever runs it can't read what you share. Your secret is encrypted on your device, and the key never reaches the server.
about-body-3 = This site is one instance of { -brand }, run by the operator named on the contact page. The software is open source, and anyone can run their own.
about-how-link = Read how it works
about-project-link = About the { -brand } project

## Contact

contact-title = Contact us
contact-lead = We'd like to hear from you.
contact-general-title = General questions
contact-general-body = For questions, feedback or anything else, email us at:
contact-security-title = Reporting a security issue
contact-security-body = If you've found a vulnerability, please tell us privately first so we can fix it before it's made public.
contact-security-link = Read our security policy
contact-no-secrets = Please never email us secret links or their contents. We don't need them to help you.

## Errors

error-badge = Error
setup-title = This site is not set up yet
setup-intro = It serves nothing public until its operator has finished three things in the admin panel:
setup-step-key = created an admin API key (the first one is created with the bootstrap credential from the server's environment),
setup-step-name = given the site a name,
setup-step-contact = given it a contact address.
setup-login = Open the admin panel
error-404-title = Page not found
error-404-body = This page doesn't exist. If you followed a secret link, the secret may have expired or already been opened.
error-500-title = Something went wrong
error-500-body = Something unexpected happened on our side. Please try again in a moment.
error-home-link = Go to the home page

## Admin

admin-title = Admin
admin-nav-dashboard = Dashboard
admin-nav-settings = Settings
admin-nav-keys = API keys
admin-logout = Sign out
admin-bootstrap-notice = You're signed in with the bootstrap token. Create an admin API key, then remove SHH_ADMIN_TOKEN from the environment; the token stops working as soon as an admin key exists.
admin-login-title = Sign in
admin-login-intro = Use an admin API key, or the bootstrap token from the environment on a fresh install.
admin-login-label = API key or bootstrap token
admin-login-submit = Sign in
admin-login-failed = That key didn't work.
admin-login-limited = Too many attempts. Wait a little and try again.
admin-login-new-key = Your first admin key. Copy it now; it won't be shown again. The bootstrap session has ended, so sign in with the key to continue.
admin-dashboard-title = Overview
admin-stat-active = Active secrets
admin-stat-created = Created
admin-stat-viewed = Viewed
admin-stat-burned = Burned
admin-stat-expired = Expired
admin-stat-removed = Removed
admin-stat-reports = Reports
admin-daily-title = Last 30 days
admin-daily-day = Day (UTC)
admin-daily-empty = Nothing happened yet.
admin-settings-title = Settings
admin-settings-intro = Changes apply immediately. Only values that differ from the defaults are stored, so a future default change reaches this instance unless you've chosen your own value.
admin-settings-saved = Saved.
admin-settings-save = Save settings
admin-settings-default = Default:
setting-site_name = Site name
setting-site_name-help = Shown in the page title and footer. Required: the site serves nothing public until it has a name and a contact address, and neither can be cleared once set.
setting-contact_email = Contact email
setting-contact_email-help = Shown on the contact page, and used for security reports while no separate address is set. Required, like the site name.
setting-security_email = Security email
setting-security_email-help = For vulnerability reports, shown on the contact page.
setting-source_url = Source code link
setting-source_url-help = Shown in the footer. Point it at your fork if you run modified code; empty hides the link.
setting-project_url = Project link
setting-project_url-help = The project's own page, shown in the footer as "Project"; empty hides the link. Content pages use it for {"{{project_url}}"}, falling back to the source code link.
setting-padding_mode = Padding mode
setting-padding_mode-help = padme pads to size classes with at most 12% overhead; buckets uses the fixed ladder below.
setting-padding_min = Minimum padded size (bytes)
setting-padding_min-help = Every secret is padded to at least this, so small files look like text.
setting-padding_ladder = Bucket ladder (bytes, comma-separated)
setting-padding_ladder-help = Only used in buckets mode.
setting-claim_window_secs = Claim window (seconds)
setting-claim_window_secs-help = How long the client that revealed a single-view secret may re-download it.
setting-min_ttl_secs = Minimum lifetime (seconds)
setting-min_ttl_secs-help = Shortest expiry the API accepts.
setting-max_ttl_secs = Maximum lifetime (seconds)
setting-max_ttl_secs-help = Longest expiry the API accepts; capped at 14 days.
setting-default_ttl_secs = Default lifetime (seconds)
setting-default_ttl_secs-help = Preselected on the create form.
setting-ttl_presets = Lifetime presets (seconds, comma-separated)
setting-ttl_presets-help = The choices offered on the create form.
setting-text_max_bytes = Text limit (bytes)
setting-text_max_bytes-help = A hint for clients; the server only enforces blob sizes.
setting-files_enabled = Files enabled
setting-files_enabled-help = When off, the file input is hidden and the API refuses anything larger than the biggest possible text secret. The server can't tell files from text, so size is the only lever it has.
setting-inline_enabled = Store small secrets in the database
setting-inline_enabled-help = When off, every secret goes to the external tier regardless of size. Needs SHH_STORAGE set to local or s3; otherwise it is ignored.
setting-regions = Regions (JSON)
setting-regions-help = Sibling instances as a JSON list of objects with code, name and url. Empty hides the selector.
setting-allowed_origins = Allowed origins (comma-separated)
setting-allowed_origins-help = Other sites whose frontends may call the API from a browser, as https:// origins (scheme and host, optional port, nothing else). This site is always allowed; empty means only this site.
setting-daily_retention_days = Keep per-day stats for (days)
setting-daily_retention_days-help = Older days are added into their year's 1 January row of the same table and then deleted, so totals never shrink but old days lose their resolution. -1 keeps every day forever.
setting-rate_create_per_hour = Rate limit: create (per hour)
setting-rate_create_per_hour-help = Per client. 0 disables.
setting-rate_reveal_per_hour = Rate limit: reveal (per hour)
setting-rate_reveal_per_hour-help = Per client. 0 disables.
setting-rate_confirm_per_hour = Rate limit: confirm (per hour)
setting-rate_confirm_per_hour-help = Per client. 0 disables.
setting-rate_burn_per_hour = Rate limit: burn (per hour)
setting-rate_burn_per_hour-help = Per client. 0 disables.
setting-rate_report_per_hour = Rate limit: report (per hour)
setting-rate_report_per_hour-help = Per client. 0 disables.
setting-rate_login_per_hour = Rate limit: admin login (per hour)
setting-rate_login_per_hour-help = Per client. 0 disables.
setting-rate_user_multiplier = API key limit multiplier
setting-rate_user_multiplier-help = Requests with a user API key get this many times the anonymous limits.
setting-salt_rotation_secs = Rate-limit salt rotation (seconds)
setting-salt_rotation_secs-help = After rotation, nothing from before can be linked to anything after.
setting-require_api_key_for_create = Require an API key to create secrets
setting-require_api_key_for_create-help = For private instances. Reveal, burn and report stay open.
admin-keys-title = API keys
admin-keys-intro = Admin keys sign in here. User keys raise the API rate limits for integrations and, if required, allow creating secrets. Keys are stored hashed and shown only once.
admin-keys-new-title = Create a key
admin-keys-name = Name
admin-keys-scope = Scope
admin-scope-user = user
admin-scope-admin = admin
admin-keys-create = Create key
admin-keys-created-title = New key
admin-keys-created = Copy it now. It won't be shown again, and it can't be recovered.
admin-keys-invalid = Give the key a name of up to 80 characters and pick a scope.
admin-keys-empty = No keys yet.
admin-keys-col-created = Created
admin-keys-col-last-used = Last used
admin-keys-never = never
admin-keys-delete = Delete
admin-keys-actions = Actions
admin-keys-end-sessions = End sessions
error-400-title = Bad request
error-400-body = The request couldn't be understood.
error-403-title = Not allowed
error-403-body = The form was missing its security token. Go back, reload the page and try again.

## Report and regions

nav-report = Report a link
report-badge = Abuse report
report-title = Report a secret link
report-intro = Paste a link you believe shares something it shouldn't. If the secret is still active it is removed immediately. We can't see what it contains, so there is nothing to review and nothing to tell you.
report-link-label = Secret link
report-link-placeholder = https://…/s#…
report-link-help = The full link including the part after the #. It is used only to find the secret; it is not stored.
report-submit = Remove this secret
report-working = Sending…
report-error-invalid = That doesn't look like a secret link from this site.
report-done-badge = Received
report-done-title = Thanks, that's handled.
report-done-body = If that link pointed at an active secret, it is gone now. We keep a record that a report was received, nothing more.
region-label = Region:
region-choose = Choose
admin-settings-group-general = General
admin-settings-group-secrets = Secrets
admin-settings-group-storage = Storage
admin-settings-group-limits = Limits
admin-settings-group-stats = Statistics
admin-settings-group-other = Other
