# SEC

**sec** is a tool to encrypt/decrypt files (also large ones) easily. The only thing you have to manage (and store)
is the passphrase used to encrypt your file(s).

## Purpose

It's main purpose is to encrypt files which contain sensible data like passwords or other stuff that you need to publish
on some public/private repository.

## Installation

A script to install the latest release of sec from Forgejo.

Usage:

> curl -skSL https://raw.githubusercontent.com/pietrangelo/sec/refs/heads/main/install.sh | bash

This script will:
1. Detect the user's OS and architecture.
2. Fetch the latest release from this repo.
3. Download the correct release asset.
4. Move the binary to /usr/local/bin.
5. Make the binary executable.

**Note:** For Windows users: to download the latest version go to: https://github.com/pietrangelo/sec/releases

## Architecture summary

**User Input**: The flags (-file, -mode, -pass) enter the `sec` tool.

**Validation**: The app checks if the file exists and the passphrase is not empty.

**Setup**:

`Argon2` runs to turn the password into a 32-byte key.

`ChaCha20` initialises.

**The Loop (Streaming)**:

1. Reads 64KB chunk.

2. Encrypts chunk.

3. Increments Nonce.

4. Writes chunk to .tmp.

5. Updates Progress Bar.

6. Finalisation: The .tmp file replaces the original file on disk.

## Use sec with git

To use the `sec` tool with git we'll use **Git Filters** which will make encryption transparent, so that on:
- **Checkout**: Git decrypts the file automatically when you pull/checkout. We see text in clear in the editor/IDE.
- **Stage**: Git encrypts the file automatically when we `git add`. The repo sees binary data.

### Configure Git

We need to tell Git about our `sec` tool using custom filters. We can create them both per repository or globally.

```bash
# Define the 'clean' filter (Runs on 'git add' -> encrypts)
git config filter.sec.clean "sec -mode=encrypt -file=-"

# Define the 'smudge' filter (Runs on 'checkout' -> decrypts)
git config filter.sec.smudge "sec -mode=decrypt -file=-"

# Tell Git this filter is required (prevents committing unencrypted if sec tool fails)
config filter.sec.required true
```

To assign files to the filter we need to create a `.gitattributes` file in the root of our repository.

```bash
# Encrypt all .secret files
*.secret filter=sec

# Encrypt specific config files
config.json filter=sec
```

Because Git runs these commands in the background, we cannot type the password every time. We must set the environment
 variable in our terminal session.

```bash

# 1. Set your password for the session
export SEC_TOOL_PASS="my-super-secret"

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

If we don't want to export the password every time, we can create a wrapper script.

Create `/usr/local/bin/git-encrypt-wrapper`:

```bash

#!/usr/bin/env bash
# Hardcode password or fetch from a Vault/Keyring
export SEC_TOOL_PASS="correct-horse-battery-staple"
/usr/local/bin/sec "$@"
```
Then update our git config to use git-encrypt-wrapper instead of sec.
