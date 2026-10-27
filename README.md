# adcheck

adcheck is a read-only Active Directory attack-path **audit** orchestrator for Kali Linux. Given a domain, a domain controller, and (optionally) a set of low-privilege credentials, it runs a battery of thirteen checks — wrapping tools like netexec, certipy-ad, bloodhound-ce-python, pre2k, sccmhunter, and rpcclient, plus internal ldap3 lookups — and consolidates every result into a single severity-rated findings set with JSON, text, and HTML reports. It performs checks only: adcheck never exploits, writes to, or otherwise modifies any target.

## Checks

| id | What it detects | Backend | Creds required |
|---|---|---|---|
| adcs | AD CS template/CA misconfigurations (ESC1–ESC8 family, dangerous enrollment rights) | certipy | Yes |
| adfs | ADFS presence (federation endpoints / `adfs` names) | internal (requests) | No |
| azuresso | `AZUREADSSOACC` computer account (Azure AD Connect Seamless SSO attack path) | internal ldap3 | Yes |
| bloodhound | Full domain collection (`.zip`) for BloodHound CE ingestion | bloodhound-ce-python | Yes |
| gpp | `cpassword` credentials in Group Policy Preferences XML on SYSVOL | netexec | Yes |
| ldapsec | LDAP signing not required / channel binding not enforced on the DC | internal ldap3 | Yes |
| maq | `ms-DS-MachineAccountQuota` > 0 — any domain user can add computer accounts (RBCD path) | netexec / internal ldap3 | Yes |
| nullrpc | Anonymous (null-session) RPC access to the DC: user/info enumeration | rpcclient | No |
| pre2k | Pre-created computer accounts still using the computer-name password | pre2k | Yes |
| sccm | SCCM/MECM infrastructure exposure (site servers, management points, credential paths) | sccmhunter | Yes |
| shares | Readable SMB shares on targets | netexec | Yes |
| smbsigning | SMB signing not required (relay-able hosts, written to `smb_relay_targets.txt`) | netexec | No |
| webdav | WebClient (WebDAV) service active on targets (HTTP coercion path) | netexec | Yes |

Checks that need credentials are skipped automatically when none are supplied; checks whose backend tool is missing are also skipped, with the reason printed. See `--list` for the live inventory.

## Installation (Kali)

```bash
# Python dependencies (ldap3, requests)
pip install -r requirements.txt

# netexec, bloodhound-ce-python, rpcclient
sudo apt install netexec bloodhound-ce.py samba-common-bin

# certipy-ad
pipx install certipy-ad

# pre2k
pipx install git+https://github.com/garrettfoster13/pre2k

# sccmhunter (no package — run from a clone)
git clone https://github.com/garrettfoster13/sccmhunter
cd sccmhunter && pip install -r requirements.txt && cd ..
```

Tools are resolved from `$PATH` at startup (`nxc`/`netexec`, `certipy-ad`/`certipy`, `bloodhound-ce-python`/`bloodhound-python`, `pre2k`, `sccmhunter`, `rpcclient`). Point at non-standard locations with `--sccmhunter /path/sccmhunter.py` and `--pre2k /path/pre2k`.

## Usage

```bash
./adcheck.sh -d corp.local --dc-ip 10.0.0.10 -u lowpriv -p 'Passw0rd' --targets 10.0.0.0/24 -o results/
```

`adcheck.sh` is a thin wrapper; the equivalent from the repo root is:

```bash
python3 -m adcheck -d corp.local --dc-ip 10.0.0.10 -u lowpriv -p 'Passw0rd' --targets 10.0.0.0/24 -o results/
```

Options: `-d/--domain`, `--dc-ip`, `--dc-fqdn`, `-u/--username`, `-p/--password`, `-H/--hashes` (`LM:NT` or `:NT`), `-k/--kerberos`, `--targets` (IP, CIDR, or file with one target per line — defaults to `--dc-ip`), `-o/--output`, `--checks`, `--skip`, `--timeout` (per-tool seconds, default 300), `--sccmhunter PATH`, `--pre2k PATH`, `--no-color`, `--list`.

List all discovered checks and exit:

```bash
./adcheck.sh --list
```

Unauthenticated-only run (no creds — everything needing auth is skipped):

```bash
./adcheck.sh -d corp.local --dc-ip 10.0.0.10 --targets 10.0.0.0/24 --checks smbsigning,nullrpc,adfs
```

Run everything except the slow/noisy ones:

```bash
./adcheck.sh -d corp.local --dc-ip 10.0.0.10 -u lowpriv -p 'Passw0rd' --skip bloodhound,sccm
```

Pass-the-hash instead of a password:

```bash
./adcheck.sh -d corp.local --dc-ip 10.0.0.10 -u lowpriv -H ':31d6cfe0d16ae931b73c59d7e0c089c0'
```

Kerberos authentication (`-k` — set `--dc-fqdn` and make sure your KDC/DNS resolve):

```bash
./adcheck.sh -d corp.local --dc-ip 10.0.0.10 --dc-fqdn dc01.corp.local -u lowpriv -p 'Passw0rd' -k
```

## Output

Everything lands in the output directory (`-o`, default `adcheck_<domain>_<timestamp>/`):

```
results/
├── findings.json          # machine-readable findings + run metadata
├── summary.txt            # severity counts and one line per non-OK finding
├── report.html            # standalone HTML report grouped by check
├── raw/                   # full stdout/stderr of every tool invocation (<check>.log)
│   └── smb_relay_targets.txt  # hosts with SMB signing not required (smbsigning check)
├── bloodhound/            # BloodHound CE collection zips (*.zip)
└── sccm/                  # sccmhunter working directory (CSV output)
```

## Severity levels

| Severity | Meaning |
|---|---|
| OK | Check ran; the tested configuration is not vulnerable / no exposure found |
| INFO | Neutral observation, context, or a check-level note (e.g. inconclusive result) |
| LOW | Minor weakness or hygiene issue |
| MEDIUM | Meaningful misconfiguration or exposure that enables an attack path |
| HIGH | Directly exploitable weakness / strong attack-path primitive |

## Caveats

- Internal LDAP checks (`maq`, `azuresso`, `ldapsec`) bind with ldap3 and reach full fidelity only with **password** authentication; pass-the-hash binds are best-effort.
- Checks only, by design: adcheck audits and reports — it never attempts exploitation or changes target state.
- Output parsers are best-effort against tool output formats, which change between versions. When a finding matters, verify it against the tool's own log in `raw/*.log`.
- Missing tools and missing credentials never abort a run; affected checks are skipped and the reason is printed.
- Per-tool timeout defaults to 300 s (`--timeout`); BloodHound collection is allowed at least 900 s internally.
