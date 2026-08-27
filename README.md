# Admin Section Password Gate

A tiny WordPress **must-use plugin** that puts a second password in front of
specific wp-admin pages (and their REST API endpoints) — for example, locking
the [Code Snippets](https://wordpress.org/plugins/code-snippets/) editor
behind an extra password so it isn't just one click away for every
administrator.

Because it's a **must-use (mu) plugin**, it loads automatically and can't be
turned off from the Plugins screen the way a normal plugin can — which is the
point, for something meant to restrict access.

## Features

- Password-protect one or more wp-admin pages by slug
- Optionally blocks the matching REST API namespace too, so the lock can't be
  bypassed by calling the plugin's REST endpoints directly
- Lockout after repeated wrong passwords (default: 5 tries → 15 minute cooldown)
- Unlock persists for 24 hours (configurable) via a signed, `httponly` cookie
- No database tables, no settings page — one file, edit a few constants

## Installation

1. Download `admin-section-password-gate.php` from this repo.
2. Generate a password hash (see below) and paste it into `$password_hash`
   inside the file.
3. Add the admin page slug(s) you want protected to `$protected_page_slugs`.
4. (Optional) Add REST namespaces to `$protected_rest_namespaces`.
5. Upload the file to `wp-content/mu-plugins/` on your site (create that
   folder if it doesn't exist). No activation step is needed.

### Generating a password hash

Never put a plain-text password in the file — only its hash. Run this once,
in any terminal that has PHP available:

```bash
php -r "echo password_hash('YOUR-STRONG-PASSWORD', PASSWORD_DEFAULT);"
```

Copy the output (starts with `$2y$10$...`) into `$password_hash`.

### Finding a page slug

Open the admin page you want to protect and look at the URL:

```
wp-admin/admin.php?page=code-snippets
                         ^^^^^^^^^^^^^ this is the slug
```

### Finding a REST namespace

Open the protected page, open your browser's DevTools → Network tab, use the
plugin normally, and look for requests to a URL like:

```
/wp-json/code-snippets/v1/...
          ^^^^^^^^^^^^^^^^ this is the namespace
```

## Configuration reference

| Setting | Default | Meaning |
|---|---|---|
| `$password_hash` | — | Output of `password_hash()`, required |
| `$protected_page_slugs` | Code Snippets slugs | Exact `?page=` values to lock |
| `$protected_rest_namespaces` | `code-snippets/v1` | REST namespaces to lock |
| `$max_attempts` | `5` | Wrong passwords allowed before lockout |
| `$lockout_minutes` | `15` | Lockout duration |
| `$unlocked_hours` | `24` | How long a successful unlock lasts |

## How it works, briefly

The plugin hooks into `admin_init` (every wp-admin page load) and, if REST
namespaces are configured, `rest_pre_dispatch` (every REST API request). If
the request matches something in the protected lists and the visitor hasn't
already unlocked it, WordPress's normal rendering is stopped and a password
form is shown instead. A correct password sets a cookie containing an
HMAC-signed token (tied to the user, the password hash, and the current
day) — the site verifies this token rather than trusting the cookie's raw
value.

## Limitations

This is a convenience/deterrent layer on top of WordPress's own permission
system (`manage_options`) — it only tightens access, never loosens it. It is
**not** a replacement for strong admin passwords, two-factor authentication,
or limiting how many people have admin/file access in the first place.
Anyone with direct file (FTP/SFTP) or `wp-config.php` access could read or
remove this file.

