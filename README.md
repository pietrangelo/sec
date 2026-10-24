# SEC

**sec** is a tool to encrypt/decrypt files (also large ones) easily. The only thing you have to manage (and store)
is the passphrase used to encrypt your file(s).

## Purpose

It's main purpose is to encrypt files which contain sensible data like passwords or other stuff that you need to publish
on some public/private repository.

## Installation

A script to install the latest release of sec from GitHub.

Usage:

> curl -fsSL https://raw.githubusercontent.com/pietrangelo/sec/refs/heads/main/install.sh | bash

This script will:
1. Detect the user's OS and architecture.
2. Fetch the latest release from this repo.
3. Download the correct release asset.
4. Move the binary to /usr/local/bin.
5. Make the binary executable.

**Note:** For Windows users: to download the latest version go to: https://github.com/pietrangelo/sec/releases

## Keys and passphrases

sec accepts either a random key or a passphrase:

```bash
# Recommended: a random 256-bit key, stored outside the repository
sec -mode=genkey > ~/.config/sec/project.key
sec -mode=encrypt -file=secrets.json -keyfile=~/.config/sec/project.key
# or: export SEC_TOOL_KEY="$(cat ~/.config/sec/project.key)"

# Or a passphrase, stretched with Argon2id
export SEC_TOOL_PASS="a long passphrase"
sec -mode=encrypt -file=secrets.json
```

A key is the better choice for automation (git filters, CI, cloud sessions): it is
required for `-deterministic` and it skips the Argon2id cost on every file. The
`-pass` flag still works but is deprecated, because command line arguments are
visible to other processes and end up in shell history.

## File format (v2)

```
"SEC\x02" | kdf | [argon2id: time, memory, threads, salt] | nonce prefix (16) | chunks
```

- **Key derivation**: the master key is the raw key, or Argon2id(passphrase, salt)
  with t=3, 64 MiB, 4 threads (RFC 9106). The parameters are stored in the header,
  so they can be raised later without breaking old files.
- **Per-file key**: HKDF-SHA256(master, nonce prefix) gives each file its own key.
- **Encryption**: XChaCha20-Poly1305 over 64 KiB chunks, using the STREAM
  construction: each chunk's nonce carries a counter and its associated data carries
  the header and a "final chunk" flag. Reordered, dropped, truncated or appended
  chunks are all rejected, as is any change to the header.
- **Deterministic mode** (`-deterministic`, key only): the nonce prefix is an
  HMAC-SHA256 of the plaintext (a synthetic IV, as in git-crypt), so encrypting the
  same file twice gives the same bytes. Git filters need this, otherwise every
  `git status` reports encrypted files as modified. It reveals only whether two
  files are identical.
- **Files**: in file mode the output goes to a private temporary file that replaces
  the original, keeping its permissions, only after the whole file was processed
  and authenticated.
- **Legacy**: files written by sec v1 are still decrypted (with the passphrase), but
  v1 cannot detect truncation, so re-encrypt them.

## Use sec with git

To use the `sec` tool with git we'll use **Git Filters** which will make encryption transparent, so that on:
- **Checkout**: Git decrypts the file automatically when you pull/checkout. We see text in clear in the editor/IDE.
- **Stage**: Git encrypts the file automatically when we `git add`. The repo sees binary data.

### Configure Git

We need to tell Git about our `sec` tool using custom filters. We can create them both per repository or globally.

```bash
# Define the 'clean' filter (Runs on 'git add' -> encrypts, same output for same input)
git config filter.sec.clean "sec -mode=encrypt -deterministic -file=-"

# Define the 'smudge' filter (Runs on 'checkout' -> decrypts)
git config filter.sec.smudge "sec -mode=decrypt -file=-"

# Tell Git this filter is required (prevents committing unencrypted if sec tool fails)
git config filter.sec.required true
```

To assign files to the filter we need to create a `.gitattributes` file in the root of our repository.

```bash
# Encrypt all .secret files
*.secret filter=sec

# Encrypt specific config files
config.json filter=sec
```

Because Git runs these commands in the background, we cannot type a secret every time. We must set the key in an
environment variable in our terminal session.

```bash

# 1. Set your key for the session
export SEC_TOOL_KEY="$(cat ~/.config/sec/project.key)"

# 2. Create a secret file
echo "This is a secret" > data.secret

# 3. Add it to Git
git add data.secret
# (At this moment, Git piped "This is a secret" -> sec -> Blob)

# 4. Commit
git commit -m "Add secret"
```

#### What just happened?

**On our disk**: `data.secret` is still plain text! We can edit it normally.

**In the Git repo**: The file is fully encrypted. If we push this to GitHub/Whatever, they only see garbage.

**When we pull**: Git pulls the encrypted blob -> pipes to sec -mode=decrypt -> writes plain text to our disk.

#### Automating the Password (Optional)

If we don't want to export the key every time, we can create a wrapper script.

Create `/usr/local/bin/git-encrypt-wrapper`:

```bash

#!/usr/bin/env bash
# Read the key from a file outside the repository, or fetch it from a Vault/Keyring
export SEC_TOOL_KEY="$(cat ~/.config/sec/project.key)"
/usr/local/bin/sec "$@"
```
Then update our git config to use git-encrypt-wrapper instead of sec.
