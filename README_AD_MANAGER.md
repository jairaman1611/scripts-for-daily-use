# AD Manager — Interactive Active Directory Management Tool

An interactive Python CLI tool for managing Windows Active Directory from macOS via LDAP/LDAPS. Designed for IT administrators who need to manage multiple AD Domain Controllers seamlessly.

## Features

- 🔐 **Multi-DC Support** — Manage multiple Windows Domain Controllers from a single interface
- 🔑 **Password Reset** — Securely reset user passwords with optional force-change-on-login
- 🔓 **Account Unlock** — Unlock locked-out user accounts
- 👤 **User Management** — Create new AD users with automatic DN generation
- 👥 **Group Management** — Add/remove users from AD security groups
- 🔍 **User Lookup** — Search users by username, email, or display name
- 🛡️ **Permissions Control** — Enable/disable accounts and manage descriptions
- 🔒 **LDAPS Support** — Automatic fallback from LDAPS (636) to LDAP (389)
- 🎨 **Color-coded Output** — Clear visual feedback with emoji indicators
- 🐛 **Debug Mode** — Optional verbose logging for troubleshooting

## Installation

### Prerequisites
- Python 3.6+
- macOS with network access to Windows AD Domain Controllers
- Active VPN connection to the AD network (if required)

### Setup

```bash
# Install required dependency
pip3 install ldap3

# Make script executable (optional)
chmod +x ad_manager.py
```

## Usage

### Basic Launch

```bash
python3 ad_manager.py
```

### Debug Mode (Verbose Logging)

```bash
python3 ad_manager.py --debug
```

## Workflow

### 1. Initial Setup
```
┌─────────────────────────────────────────────┐
│ Planview AD Manager — Interactive CLI Tool  │
└─────────────────────────────────────────────┘
  Same credentials for all DCs? [Y/n]: 
  Username (DOMAIN\user or user@domain): 
  Password: 
```

**Options:**
- **Y (default)** — Use same credentials for all Domain Controllers
- **N** — Prompt for different credentials per DC

### 2. Select Domain Controller(s)

```
  Select DC(s):
    [1]  UK    uk1-dc10.eu.uk.com
    [2]  NL    nl1-dc01.eu.nl.com
    [3]  SV    sv1-dc01.sv.zen.com
    [4]  NJ    nj1-dc01.nj.zen.com
    [5]  All DCs
    [6]  Select multiple — e.g. 1,3
```

**Examples:**
- `1` — Single DC (UK)
- `1,3` — Multiple DCs (UK and SV)
- `5` — All Domain Controllers

### 3. Select Operation

```
  Operation:
    [1]  Reset password
    [2]  Unlock account
    [3]  Enable / Disable / Set description
    [4]  Change group membership
    [5]  Create new user
    [6]  Look up user
    [0]  Exit
```

## Operations Guide

### 1. Reset Password

Reset a user's password with optional forced change on next login.

```
Password Reset — UK
  Username / email: jdoe
  
  [ UK ]
  Name             Jane Doe
  Login            jdoe
  Email            jane.doe@company.com
  Status           Enabled
  Groups
    • Domain Users
    • IT_Staff
    
  New password: ••••••••
  Confirm: ••••••••
  Force change on next login? [y/N]: y
  Reset password for Jane Doe? [y/N]: y
  ✓  Password reset — Jane Doe on UK
  ✓  Will be prompted to change password on next login
```

**Requirements:**
- Minimum 8 characters
- Password confirmation required
- Admin account must have rights to modify passwords

### 2. Unlock Account

Unlock a user account after failed login attempts.

```
Unlock Account — UK
  Username: jdoe
  
  [ UK ]
  Name             Jane Doe
  Login            jdoe
  Status           Enabled
  
  Unlock Jane Doe? [y/N]: y
  ✓  Account unlocked — Jane Doe on UK
```

### 3. Enable / Disable / Set Description

Manage account status and metadata.

```
Account Permissions — UK
  Username: jsmith
  
  [ UK ]
  Name             John Smith
  Login            jsmith
  Status           Enabled
  
  [1] Enable   [2] Disable   [3] Set description
  Choice: 2
  Disable John Smith? [y/N]: y
  ✓  Account disabled — John Smith
```

**Options:**
- **[1] Enable** — Re-enable a disabled account
- **[2] Disable** — Disable an active account
- **[3] Set description** — Update user's description field

### 4. Change Group Membership

Add or remove users from security groups.

```
Group Membership — UK
  Username: jdoe
  
  [ UK ]
  Name             Jane Doe
  Groups
    • Domain Users
    • IT_Staff
    • HR_Staff
    • … and 2 more
  
  [1] Add to group   [2] Remove from group
  Choice: 1
  Group name: Finance_Approvers
  Add to group Finance_Approvers for Jane Doe? [y/N]: y
  ✓  Done — Jane Doe / Finance_Approvers on UK
```

### 5. Create New User

Create a new AD user account with optional group membership.

```
Create User — UK
  First name: Jane
  Last name : Smith
  Username [jsmith]: jsmith
  UPN [jsmith@eu.uk.com]: jane.smith@eu.uk.com
  Email [jane.smith@eu.uk.com]: jane.smith@company.com
  Title (optional): Senior Manager
  Department (optional): Finance
  
  OU:  [1] CN=Users (default)   [2] Custom path
  Choice [1]: 2
  OU path (e.g. OU=IT,OU=Staff): OU=Finance,OU=Staff
  
  Password: ••••••••
  Confirm : ••••••••
  Force change on login? [Y/n]: y
  Groups to add (comma-separated, optional): Finance_Approvers, Domain Users
  
  Summary:
  Name                Jane Smith
  Username            jsmith
  UPN                 jane.smith@eu.uk.com
  DN                  CN=Jane Smith,OU=Finance,OU=Staff,DC=eu,DC=uk,DC=com
  Groups              Finance_Approvers, Domain Users
  
  Create user on UK? [y/N]: y
  ✓  Account created
  ✓  Password set
  ✓  Account enabled
  ✓  Added to Finance_Approvers
  ✓  Added to Domain Users
  ✅  Jane Smith (jsmith) created on UK
```

**Default Values:**
- **Username** — Auto-generated from first initial + last name (lowercase)
- **UPN** — Auto-generated from username@domain
- **Email** — Defaults to UPN
- **OU** — Defaults to CN=Users
- **Force change** — Yes (user must change password on first login)

### 6. Look Up User

Search and display detailed user information.

```
Look Up User — UK
  Username / email / display name: jdoe
  
  [ UK ]
  Name             Jane Doe
  Login            jdoe
  Email            jane.doe@company.com
  Status           Enabled
  Groups
    • Domain Users
    • IT_Staff
    • HR_Management
    • … and 1 more
  
  CN=Jane Doe,CN=Users,DC=eu,DC=uk,DC=com
```

**Search Fields:**
- Username (sAMAccountName)
- Email (userPrincipalName)
- Display name
- Common name (cn)

## Domain Controllers

The script is preconfigured with these Domain Controllers:

| ID | Host | Base DN | Region |
|---|---|---|---|
| UK | uk1-dc10.eu.uk.com | DC=eu,DC=uk,DC=com | Europe - UK |
| NL | nl1-dc01.eu.nl.com | DC=eu,DC=nl,DC=com | Europe - Netherlands |
| SV | sv1-dc01.sv.zen.com | DC=sv,DC=zen,DC=com | Sweden |
| NJ | nj1-dc01.nj.zen.com | DC=nj,DC=zen,DC=com | New Jersey |

### Adding/Modifying Domain Controllers

Edit the `DCS` list in the script (around line 59):

```python
DCS = [
    {"id":"UK", "host":"uk1-dc10.eu.uk.com",  "base_dn":"DC=eu,DC=uk,DC=com"},
    {"id":"NL", "host":"nl1-dc01.eu.nl.com",  "base_dn":"DC=eu,DC=nl,DC=com"},
    {"id":"SV", "host":"sv1-dc01.sv.zen.com", "base_dn":"DC=sv,DC=zen,DC=com"},
    {"id":"NJ", "host":"nj1-dc01.nj.zen.com", "base_dn":"DC=nj,DC=zen,DC=com"},
]
```

## Connection Details

### Ports & Protocols

- **LDAPS (636)** — Primary secure connection (TLS)
- **LDAP (389)** — Fallback if LDAPS unavailable

The tool automatically:
1. Attempts LDAPS first (port 636)
2. Falls back to LDAP (port 389) if connection fails
3. Reports which protocol was used

### Authentication

- **Method** — NTLM (Windows-native authentication)
- **Format** — `DOMAIN\username` or `username@domain`
- **Credentials** — Entered securely via getpass (no echo)

### SSL/TLS

- **Validation** — Disabled for self-signed certificates
- **Custom CAs** — Modify `ssl.CERT_NONE` in the `connect()` function if needed

## Error Messages & Troubleshooting

### ❌ ldap3 not installed

```
❌  ldap3 not installed.  Run:  pip3 install ldap3
```

**Fix:** Install the required package:
```bash
pip3 install ldap3
```

### ❌ Authentication failed for [DC_ID] — wrong credentials?

**Causes:**
- Invalid username or password
- User doesn't have AD admin privileges
- Account is locked or disabled

**Solutions:**
- Verify credentials
- Check user has AD admin rights
- Ensure user account is active
- Try with different credentials for that DC

### ❌ Cannot reach [DC_ID] — VPN connected?

**Causes:**
- Network unreachable
- Firewall blocking ports 389/636
- VPN disconnected
- Domain Controller offline

**Solutions:**
- Verify VPN connection is active
- Check firewall/network connectivity
- Confirm DC host is reachable: `ping uk1-dc10.eu.uk.com`
- Test ports: `nc -zv uk1-dc10.eu.uk.com 636`
- Contact network admin if DC is offline

### ❌ Failed: [error message]

**In Debug Mode:**
```bash
python3 ad_manager.py --debug
```

This shows full stack traces to identify root causes.

## Common Use Cases

### Scenario 1: Bulk Password Reset

```
1. Same credentials? [Y] (use admin account)
2. Select DC: [5] (All DCs)
3. Select Operation: [1] (Reset password)
4. Enter username, new password, confirm

→ Password reset across all DCs simultaneously
```

### Scenario 2: Emergency Account Unlock

```
1. Same credentials? [Y]
2. Select DC: [1] (UK)
3. Select Operation: [2] (Unlock account)
4. Enter locked username

→ Account immediately unlocked
```

### Scenario 3: Onboard New Employee

```
1. Same credentials? [Y]
2. Select DC: [1] (UK)
3. Select Operation: [5] (Create new user)
4. Fill in details (name, email, title, department)
5. Select OU, set password, assign groups

→ Complete user created with all permissions
```

## Security Considerations

⚠️ **Important:**

1. **Credentials** — Never stored; cleared from memory after session
2. **Admin Rights** — Requires AD administrative privileges
3. **Audit Logging** — All AD operations are logged by Windows
4. **SSL/TLS** — LDAPS recommended for secure connections
5. **VPN** — Ensure secure network connection to DCs
6. **Shared Systems** — Don't run on multi-user systems without caution
7. **Password Input** — Uses `getpass` module (input not echoed)

## Keyboard Shortcuts

- **Ctrl+C** — Cancel operation gracefully
- **Ctrl+D** — Exit (EOF signal)

## Output Indicators

| Symbol | Color | Meaning |
|---|---|---|
| ✓ | Green | Success |
| ✗ | Red | Error |
| ⚠ | Yellow | Warning |
| ℹ | Cyan | Information |

## Logging & Debug

### Enable Debug Mode

```bash
python3 ad_manager.py --debug
```

Outputs:
- Full exception stack traces
- Connection details
- LDAP query results
- LDAP operation responses

## Performance Notes

- **Connection timeout** — 8 seconds per DC
- **Group display** — Shows first 6 groups (with "… and X more" indicator)
- **Large OUs** — May take longer for searches in very large directories

## Limitations

- **Single domain per DC** — One base DN per Domain Controller
- **NTLM only** — Windows authentication method
- **Interactive only** — No headless/scripted mode
- **Manual DC configuration** — Edit script to add/modify DCs
- **No group creation** — Manage membership only (create groups in ADUC)

## Requirements & Dependencies

### System Requirements
- Python 3.6+
- macOS (may work on Linux/Windows with LDAP access)
- Network access to AD Domain Controllers

### Python Dependencies
```
ldap3>=2.8.0
```

No other external dependencies required.

## License

See repository LICENSE file.

## Support & Contribution

For issues, feature requests, or contributions, please refer to the main repository.

---

**Last Updated:** 2026-05-26  
**Version:** 1.0  
**Tested With:** ldap3 3.4.x, Python 3.9+
