[![PyPi Version](https://img.shields.io/pypi/v/CredSpy.svg)](https://pypi.org/project/CredSpy/)
![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/RedByte1337?style=flat&logo=githubsponsors)](https://github.com/sponsors/RedByte1337)
[![Twitter](https://img.shields.io/twitter/follow/RedByte1337?label=RedByte1337&style=social)](https://twitter.com/intent/follow?screen_name=RedByte1337)
[![LinkedIn](https://img.shields.io/badge/in-Keanu_Nys-white?style=flat&logoColor=blue&labelColor=blue)](https://www.linkedin.com/in/keanunys/)

# CredSpy

Enumerate Microsoft Entra ID authentication methods for email addresses using the public `GetCredentialType` API. This is the same endpoint the Microsoft login page uses when you enter a username. In contrast to most tools using the GetCredentialType method, CredSpy also shows the authentication methods supported for existing accounts.

Useful for security assessments: user enumeration, preferred auth method discovery, and identifying accounts with password, Remote NGC (e.g. Passwordless Push Notification), FIDO2/passkeys, or certificate auth.

## Table of contents

- [Installation](#installation)
- [Usage](#usage)
  - [Options](#options)
- [Output](#output)
  - [CSV columns](#csv-columns)
- [How it works](#how-it-works)
- [Disclaimer](#disclaimer)

## Installation

Requires Python 3.10+.

**pipx** (recommended):

```bash
# Install pipx (skip this if you already have it)
apt install pipx
pipx ensurepath
```

```bash
# From PyPI (recommended)
pipx install credspy

# Or from GitHub
pipx install git+https://github.com/RedByte1337/CredSpy.git

# From a local clone
git clone https://github.com/RedByte1337/CredSpy.git
cd CredSpy
pipx install .
```

**pip**:

```bash
pip install .
# or run without installing
pip install -r requirements.txt
python credspy.py ...
```

After installation, run `credspy` from anywhere:

```bash
credspy -h
```

## Usage

```bash
# Single email
credspy user@example.com

# File of emails (one per line, # for comments)
credspy emails.txt

# Through a proxy (SSL verification disabled for MITM tools)
credspy emails.txt --proxy http://127.0.0.1:8080

# Export results to CSV
credspy emails.txt --csv results.csv

# Save filtered email lists (combinable)
credspy emails.txt \
  --save-existing existing.txt \
  --save-ngc ngc.txt \
  --save-password-preferred password-preferred.txt
```

### Options

| Flag | Description |
|------|-------------|
| `target` | Email address or path to a text file |
| `--proxy URL` | Route all traffic through a proxy; disables SSL verification |
| `--no-color` | Disable colored terminal output |
| `--csv FILE` | Write results to CSV |
| `--save-existing FILE` | Save emails that exist |
| `--save-ngc FILE` | Save emails with RemoteNGC (e.g. passwordless push-notification) supported |
| `--save-password-preferred FILE` | Save existing emails with password as preferred method |

If any output file already exists, you are prompted to confirm overwrite (`Y/n`).

## Output

Results stream to the terminal as each email is checked:

```
redbyte@e-corp.com              | Preferred: Fido (7)     | Supported: Password, RemoteNGC (PushNotification), Fido (Count: 3)
nonexist@e-corp.com             | IfExistsResult: NotExist (1)
admin@e-corp.com              | Preferred: Password (1)     | Supported: Password, RemoteNGC (PushNotification)
```

For fido authentication, the number of entries in the AllowList of the FidoParams returned by Microsoft is shown. This can be used as an indicator to know how many Fido auth methods the user has enrolled. However, it seems like this also includes deleted Fido keys which are not linked to the account anymore. 


A summary is printed at the end:

```
--- Summary ---
Exists: 6/7
Throttled: 0/7
Preferred: Fido 3/6, Password 2/6, ...
Supported: Password 6/6, RemoteNGC 1/6, Fido 3/6, Certificate 2/6
DomainType: Managed 6/6

--- Output files ---
CSV (results.csv): 7 entries
```

### CSV columns

`Email`, `Exists`, `PreferredType`, `HasPassword`, `RemoteNGC`, `HasFido`, `HasCertAuth`, `DomainType`

- **Exists** — enum name (`Exists`, `NotExist`, …)
- **RemoteNGC** — `PushNotification` / `ListSessions` when known, otherwise `True`/`False`

## How it works

1. Fetch a session context (`sCtx`) from the Microsoft OAuth authorize page
2. POST each username to `login.microsoftonline.com/common/GetCredentialType`
3. Parse credential flags and print / export results

No authentication required. This uses the same unauthenticated flow as the login UI.

## Disclaimer

This tool is intended for **authorized security testing and research only**. Only use it against tenants and accounts you own or have explicit written permission to test. The authors are not responsible for misuse.
