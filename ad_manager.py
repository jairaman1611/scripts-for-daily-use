#!/usr/bin/env python3
"""
ad_manager.py — Interactive Active Directory Management Tool
Connects from Mac to Windows AD Domain Controllers via LDAP/LDAPS.

Install:  pip3 install ldap3
Run:      python3 ad_manager.py
Debug:    python3 ad_manager.py --debug
"""

import sys, ssl, getpass, traceback
from typing import Optional

try:
    from ldap3 import (
        Server, Connection, ALL, NTLM, SUBTREE,
        MODIFY_REPLACE, Tls
    )
    from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError
    from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
    from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups
    from ldap3.extend.microsoft.modifyPassword import ad_modify_password
    from ldap3.extend.microsoft.unlockAccount import ad_unlock_account
except ImportError:
    print("\n❌  ldap3 not installed.  Run:  pip3 install ldap3\n")
    sys.exit(1)

DEBUG = "--debug" in sys.argv


class ADOperationError(Exception):
    """Raised when an AD operation fails — caught per-DC so other DCs still run."""
    pass


def verify_ou_exists(conn, ou_dn: str) -> bool:
    """
    Confirm the given OU DN actually exists on this DC.
    Returns True if found, False if not.
    Does NOT create the OU — errors are handled by the caller.
    """
    try:
        conn.search(ou_dn, "(objectClass=*)", search_scope="BASE",
                    attributes=["distinguishedName"])
        return bool(conn.entries)
    except Exception:
        return False

# ── colours ───────────────────────────────────────────────────────────────────
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"

def ok(m):   print(f"{C.GREEN}  ✓  {m}{C.RESET}")
def err(m):  print(f"{C.RED}  ✗  {m}{C.RESET}")
def warn(m): print(f"{C.YELLOW}  ⚠  {m}{C.RESET}")
def info(m): print(f"{C.CYAN}  ℹ  {m}{C.RESET}")
def head(m): print(f"\n{C.BOLD}{C.BLUE}{'─'*58}\n  {m}\n{'─'*58}{C.RESET}")

# ── DC definitions ────────────────────────────────────────────────────────────
#
#  upn_suffix   — appended to username for login:  firstname.lastname@nl.eu.com
#  netbios      — NETBIOS domain prefix for NTLM:  NL\firstname.lastname
#  user_logon   — canonical format shown to admin: NL\firstname.lastname
#  base_dn      — LDAP search root for this domain
#
DCS = [
    {
        "id":         "UK",
        "host":       "uk1-dc10.eu.uk.com",
        "base_dn":    "DC=eu,DC=uk,DC=com",
        "upn_suffix": "eu.uk.com",
        "netbios":    "UK",
        "user_logon": "UK\\{username}",    # UK\firstname.lastname
    },
    {
        "id":         "NL",
        "host":       "nl1-dc01.eu.nl.com",
        "base_dn":    "DC=eu,DC=nl,DC=com",
        "upn_suffix": "eu.nl.com",
        "netbios":    "NL",
        "user_logon": "NL\\{username}",    # NL\firstname.lastname
    },
    {
        "id":         "SV",
        "host":       "sv1-dc01.sv.zen.com",
        "base_dn":    "DC=sv,DC=zen,DC=com",
        "upn_suffix": "sv.zen.com",
        "netbios":    "SV",
        "user_logon": "SV\\{username}",    # SV\firstname.lastname
    },
    {
        "id":         "NJ",
        "host":       "nj1-dc01.nj.zen.com",
        "base_dn":    "DC=nj,DC=zen,DC=com",
        "upn_suffix": "nj.zen.com",
        "netbios":    "NJ",
        "user_logon": "NJ\\{username}",    # NJ\firstname.lastname
    },
]


def fmt_upn(dc: dict, username: str) -> str:
    """firstname.lastname@nl.eu.com"""
    return f"{username}@{dc['upn_suffix']}"


def fmt_logon(dc: dict, username: str) -> str:
    """NL\firstname.lastname"""
    return dc["user_logon"].format(username=username)


def default_sam(first: str, last: str) -> str:
    """firstname.lastname (Planview standard)"""
    return f"{first.lower()}.{last.lower()}"

# ── connection ────────────────────────────────────────────────────────────────
def connect(dc, user, pwd) -> Optional[Connection]:
    for port, use_ssl in [(636, True), (389, False)]:
        try:
            tls    = Tls(validate=ssl.CERT_NONE) if use_ssl else None
            server = Server(dc["host"], port=port, use_ssl=use_ssl,
                            tls=tls, get_info=ALL, connect_timeout=8)
            conn   = Connection(server, user=user, password=pwd,
                                authentication=NTLM, auto_bind=True)
            ok(f"Connected to {dc['id']} ({dc['host']}) via {'LDAPS' if use_ssl else 'LDAP'}")
            return conn
        except LDAPBindError:
            err(f"Authentication failed for {dc['id']} — wrong credentials?")
            return None
        except (LDAPSocketOpenError, Exception):
            continue
    err(f"Cannot reach {dc['id']} ({dc['host']}) — VPN connected?")
    return None

# ── helpers ───────────────────────────────────────────────────────────────────
def find_user(conn, base_dn, term):
    conn.search(base_dn,
        f"(&(objectClass=user)(objectCategory=person)"
        f"(|(sAMAccountName={term})(userPrincipalName={term})"
        f"(displayName={term})(cn={term})))",
        SUBTREE,
        attributes=["distinguishedName","sAMAccountName","displayName",
                    "mail","memberOf","userAccountControl","pwdLastSet","lockoutTime"])
    return conn.entries[0] if conn.entries else None

def find_group(conn, base_dn, name):
    conn.search(base_dn,
        f"(&(objectClass=group)(|(cn={name})(sAMAccountName={name})))",
        SUBTREE, attributes=["distinguishedName","cn","member"])
    return conn.entries[0] if conn.entries else None

def dn(e): return str(e.entry_dn)


def fetch_ous(conn, base_dn) -> list:
    """
    Fetch all Organizational Units from the DC and return as a sorted list of dicts.
    Each dict has: name, dn, path (human-readable indented path)
    """
    conn.search(
        base_dn,
        "(objectClass=organizationalUnit)",
        SUBTREE,
        attributes=["distinguishedName", "name", "description"]
    )
    ous = []
    for entry in conn.entries:
        ou_dn   = str(entry.entry_dn)
        ou_name = str(entry.name)
        # Build a readable path by stripping the base_dn and reversing OU parts
        relative = ou_dn.replace(f",{base_dn}", "")
        parts    = [p.replace("OU=","") for p in relative.split(",") if p.startswith("OU=")]
        parts.reverse()
        path = " / ".join(parts) if parts else ou_name
        ous.append({"name": ou_name, "dn": ou_dn, "path": path})
    # Sort by path so parent OUs appear before children
    ous.sort(key=lambda x: x["path"].lower())
    return ous


def select_ou(conn, base_dn, dc_id) -> str:
    """
    Interactively select an OU from the DC or enter a custom path.
    Returns the full OU DN string (e.g. OU=Debug servers,DC=nl,DC=eu,DC=com)
    """
    print(f"\n  {C.DIM}Fetching OUs from {dc_id}...{C.RESET}")
    ous = fetch_ous(conn, base_dn)

    if not ous:
        warn("No OUs found — defaulting to CN=Users")
        return f"CN=Users,{base_dn}"

    print(f"\n  {C.BOLD}Available OUs on {dc_id}:{C.RESET}")
    print(f"  {C.DIM}{'No.':<5} {'OU Path'}{C.RESET}")
    print(f"  {'─'*55}")

    for i, ou in enumerate(ous, 1):
        # Indent nested OUs visually
        depth  = ou["path"].count(" / ")
        indent = "  " * depth
        label  = ou["path"].split(" / ")[-1]
        print(f"  {C.CYAN}[{i:>2}]{C.RESET}  {indent}{label}"
              + (f"  {C.DIM}({ou['path']}){C.RESET}" if depth > 0 else ""))

    print(f"  {C.CYAN}[ 0]{C.RESET}  CN=Users (default container)")
    print(f"  {C.CYAN}[ M]{C.RESET}  Enter path manually")

    choice = input(f"\n  Select OU [0]: ").strip()

    if choice == "0" or choice == "":
        return f"CN=Users,{base_dn}"

    if choice.upper() == "M":
        manual = input("  Full OU path (e.g. OU=Debug servers,OU=PRD Users): ").strip()
        if not manual:
            return f"CN=Users,{base_dn}"
        return f"{manual},{base_dn}"

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(ous):
            selected = ous[idx]
            ok(f"Selected: {selected['path']}")
            return selected["dn"]
    except ValueError:
        pass

    warn("Invalid choice — using CN=Users")
    return f"CN=Users,{base_dn}"

def disabled(uac):
    try: return bool(int(str(uac)) & 2)
    except: return False

def show_user(e, dc_id):
    status = f"{C.RED}Disabled{C.RESET}" if disabled(e.userAccountControl) else f"{C.GREEN}Enabled{C.RESET}"
    print(f"\n  {C.BOLD}[ {dc_id} ]{C.RESET}")
    print(f"  {'Name':<16} {e.displayName}")
    print(f"  {'Login':<16} {e.sAMAccountName}")
    print(f"  {'Email':<16} {e.mail}")
    print(f"  {'Status':<16} {status}")
    groups = e.memberOf.values if hasattr(e.memberOf, 'values') else []
    if groups:
        print(f"  {'Groups':<16}")
        for g in groups[:6]:
            print(f"    {C.DIM}• {g.split(',')[0].replace('CN=','')}{C.RESET}")
        if len(groups) > 6:
            print(f"    {C.DIM}  … and {len(groups)-6} more{C.RESET}")

def confirm(msg) -> bool:
    return input(f"\n  {msg} [y/N]: ").strip().lower() == "y"

# ── operations ────────────────────────────────────────────────────────────────
def op_reset_password(conn, base_dn, dc_id):
    head(f"PASSWORD RESET — {dc_id}")
    term = input("  Username / email: ").strip()
    if not term: return
    u = find_user(conn, base_dn, term)
    if not u: err(f"User '{term}' not found on {dc_id}"); return
    show_user(u, dc_id)

    pw  = getpass.getpass("\n  New password: ")
    pw2 = getpass.getpass("  Confirm: ")
    if pw != pw2:    err("Passwords do not match"); return
    if len(pw) < 8:  err("Minimum 8 characters"); return

    force = input("  Force change on next login? [y/N]: ").strip().lower() == "y"
    if not confirm(f"Reset password for {u.displayName}?"): return

    if ad_modify_password(conn, dn(u), pw, old_password=None):
        ok(f"Password reset — {u.displayName} on {dc_id}")
        if force:
            conn.modify(dn(u), {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
            ok("Will be prompted to change password on next login")
    else:
        err(f"Failed: {conn.result}")


def op_unlock(conn, base_dn, dc_id):
    head(f"UNLOCK ACCOUNT — {dc_id}")
    term = input("  Username: ").strip()
    if not term: return
    u = find_user(conn, base_dn, term)
    if not u: err(f"User '{term}' not found"); return
    show_user(u, dc_id)
    if not confirm(f"Unlock {u.displayName}?"): return
    if ad_unlock_account(conn, dn(u)):
        ok(f"Account unlocked — {u.displayName} on {dc_id}")
    else:
        err(f"Failed: {conn.result}")


def op_permissions(conn, base_dn, dc_id):
    head(f"ACCOUNT PERMISSIONS — {dc_id}")
    term = input("  Username: ").strip()
    if not term: return
    u = find_user(conn, base_dn, term)
    if not u: err(f"User '{term}' not found"); return
    show_user(u, dc_id)
    print(f"\n  {C.CYAN}[1]{C.RESET} Enable  "
          f"  {C.CYAN}[2]{C.RESET} Disable  "
          f"  {C.CYAN}[3]{C.RESET} Set description")
    c = input("  Choice: ").strip()
    try:
        uac = int(str(u.userAccountControl))
        if c == "1":
            if not confirm(f"Enable {u.displayName}?"): return
            conn.modify(dn(u), {"userAccountControl": [(MODIFY_REPLACE, [uac & ~2])]})
            ok(f"Account enabled — {u.displayName}")
        elif c == "2":
            if not confirm(f"Disable {u.displayName}?"): return
            conn.modify(dn(u), {"userAccountControl": [(MODIFY_REPLACE, [uac | 2])]})
            ok(f"Account disabled — {u.displayName}")
        elif c == "3":
            desc = input("  New description: ").strip()
            if not desc: return
            conn.modify(dn(u), {"description": [(MODIFY_REPLACE, [desc])]})
            ok(f"Description updated")
    except ADOperationError:
        raise
    except Exception as e:
        err(f"AD operation failed on {dc_id}: {e}")
        if DEBUG: traceback.print_exc()


def op_groups(conn, base_dn, dc_id):
    head(f"GROUP MEMBERSHIP — {dc_id}")
    term = input("  Username: ").strip()
    if not term: return
    u = find_user(conn, base_dn, term)
    if not u: err(f"User '{term}' not found"); return
    show_user(u, dc_id)
    print(f"\n  {C.CYAN}[1]{C.RESET} Add to group   {C.CYAN}[2]{C.RESET} Remove from group")
    action = input("  Choice: ").strip()
    if action not in ("1","2"): return
    gname = input("  Group name: ").strip()
    if not gname: return
    g = find_group(conn, base_dn, gname)
    if not g: err(f"Group '{gname}' not found"); return
    verb = "Add to" if action == "1" else "Remove from"
    if not confirm(f"{verb} group {g.cn} for {u.displayName}?"): return
    try:
        if action == "1":
            r = ad_add_members_to_groups(conn, [dn(u)], [dn(g)])
        else:
            r = ad_remove_members_from_groups(conn, [dn(u)], [dn(g)], fix=True)
        if r: ok(f"Done — {u.displayName} / {g.cn} on {dc_id}")
        else: err(f"Failed: {conn.result}")
    except ADOperationError:
        raise
    except Exception as e:
        err(f"AD operation failed on {dc_id}: {e}")
        if DEBUG: traceback.print_exc()


def clone_groups_from_user(conn, base_dn, dc_id) -> list:
    """Look up an existing user and return their group DNs."""
    term = input("  Clone groups from username: ").strip()
    if not term: return []
    source = find_user(conn, base_dn, term)
    if not source:
        err(f"User '{term}' not found on {dc_id}")
        return []
    raw = source.memberOf.values if hasattr(source.memberOf, "values") else []
    if not raw:
        warn(f"{source.displayName} has no groups to clone")
        return []
    print(f"\n  {C.BOLD}Groups from {source.displayName}:{C.RESET}")
    for g in raw:
        cn = g.split(",")[0].replace("CN=","")
        print(f"    {C.DIM}✓  {cn}{C.RESET}")
    print(f"\n  {C.CYAN}{len(raw)} group(s){C.RESET} will be cloned")
    return list(raw)


def op_create_user(conn, base_dn, dc_id):
    head(f"CREATE USER — {dc_id}")
    first = input("  First name: ").strip()
    last  = input("  Last name : ").strip()
    if not first or not last: err("Name required"); return

    # Per-DC username format: firstname.lastname
    dc_obj    = next((d for d in DCS if d["id"] == dc_id), None)
    def_sam   = default_sam(first, last)
    def_upn   = fmt_upn(dc_obj, def_sam)   if dc_obj else f"{def_sam}@{base_dn}"
    def_logon = fmt_logon(dc_obj, def_sam) if dc_obj else def_sam

    print(f"\n  {C.DIM}Logon format for {dc_id}: {def_logon}{C.RESET}")
    sam   = input(f"  Username [{def_sam}]: ").strip() or def_sam
    upn   = input(f"  UPN      [{fmt_upn(dc_obj, sam) if dc_obj else sam}]: ").strip()             or (fmt_upn(dc_obj, sam) if dc_obj else sam)
    email = input(f"  Email    [{upn}]: ").strip() or upn
    title = input("  Title (optional): ").strip()
    dept  = input("  Department (optional): ").strip()

    # Fetch real OUs from DC and let user pick
    ou_dn = select_ou(conn, base_dn, dc_id)
    udn   = f"CN={first} {last},{ou_dn}"

    pw  = getpass.getpass("\n  Password: ")
    pw2 = getpass.getpass("  Confirm : ")
    if pw != pw2:   err("Mismatch"); return
    if len(pw) < 8: err("Min 8 chars"); return
    force = input("  Force change on login? [Y/n]: ").strip().lower() != "n"

    # ── Group assignment ──────────────────────────────────────────────────
    print(f"\n  {C.BOLD}Group assignment:{C.RESET}")
    print(f"    {C.CYAN}[1]{C.RESET}  Clone from existing user")
    print(f"    {C.CYAN}[2]{C.RESET}  Enter groups manually")
    print(f"    {C.CYAN}[3]{C.RESET}  Clone from existing user + add extra groups")
    print(f"    {C.CYAN}[4]{C.RESET}  Skip — no groups")
    grp_choice = input("  Choice [4]: ").strip() or "4"

    cloned_dns   = []
    manual_names = []

    if grp_choice in ("1", "3"):
        cloned_dns = clone_groups_from_user(conn, base_dn, dc_id)
    if grp_choice in ("2", "3"):
        raw = input("  Extra groups (comma-separated): ").strip()
        manual_names = [g.strip() for g in raw.split(",") if g.strip()]

    # ── Summary ───────────────────────────────────────────────────────────
    logon_display = fmt_logon(dc_obj, sam) if dc_obj else sam
    print(f"\n  {C.BOLD}Summary:{C.RESET}")
    print(f"  {'Name':<18} {first} {last}")
    print(f"  {'Logon':<18} {logon_display}")
    print(f"  {'UPN':<18} {upn}")
    print(f"  {'DN':<18} {udn}")
    if cloned_dns:   print(f"  {'Cloned groups':<18} {len(cloned_dns)} group(s)")
    if manual_names: print(f"  {'Manual groups':<18} {', '.join(manual_names)}")
    if not cloned_dns and not manual_names:
        print(f"  {'Groups':<18} None")

    if not confirm(f"Create user on {dc_id}?"): return

    # ── Verify OU exists on THIS DC before doing anything ─────────────────
    # Critical for multi-DC runs: each DC may have different OU structures.
    if not ou_dn.startswith("CN=Users"):
        if not verify_ou_exists(conn, ou_dn):
            err(f"OU not found on {dc_id}: {ou_dn}")
            err(f"Skipping user creation on {dc_id} — OU does not exist here.")
            err(f"No changes were made on {dc_id}.")
            return
        ok(f"OU verified on {dc_id}")

    try:
        attrs = {
            "objectClass":        ["top","person","organizationalPerson","user"],
            "sAMAccountName":     sam,
            "userPrincipalName":  upn,
            "givenName":          first,
            "sn":                 last,
            "displayName":        f"{first} {last}",
            "mail":               email,
            "userAccountControl": 514,
        }
        if title: attrs["title"]      = title
        if dept:  attrs["department"] = dept

        conn.add(udn, attributes=attrs)
        if conn.result["result"] != 0:
            err(f"Create failed: {conn.result['description']}"); return
        ok("Account created")

        if not ad_modify_password(conn, udn, pw, old_password=None):
            err(f"Password set failed: {conn.result}"); return
        ok("Password set")

        conn.modify(udn, {"userAccountControl": [(MODIFY_REPLACE, [512])]})
        if force:
            conn.modify(udn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
        ok("Account enabled")

        if cloned_dns:
            if ad_add_members_to_groups(conn, [udn], cloned_dns):
                ok(f"Cloned {len(cloned_dns)} group(s) from source user")
            else:
                warn(f"Some cloned groups failed: {conn.result}")

        for gname in manual_names:
            g = find_group(conn, base_dn, gname)
            if not g: warn(f"Group '{gname}' not found — skipped"); continue
            if ad_add_members_to_groups(conn, [udn], [dn(g)]):
                ok(f"Added to {gname}")
            else:
                warn(f"Could not add to {gname}")

        ok(f"✅  {first} {last} ({sam}) created on {dc_id}")
    except ADOperationError:
        raise
    except Exception as e:
        err(f"AD operation failed on {dc_id}: {e}")
        if DEBUG: traceback.print_exc()


def op_lookup(conn, base_dn, dc_id):
    head(f"LOOK UP USER — {dc_id}")
    term = input("  Username / email / display name: ").strip()
    if not term: return
    u = find_user(conn, base_dn, term)
    if not u: err(f"'{term}' not found on {dc_id}"); return
    show_user(u, dc_id)
    print(f"\n  {C.DIM}{dn(u)}{C.RESET}")

# ── DC selector ───────────────────────────────────────────────────────────────
def select_dcs():
    print(f"\n{C.BOLD}  Select DC(s):{C.RESET}")
    for i, dc in enumerate(DCS, 1):
        print(f"    {C.CYAN}[{i}]{C.RESET}  {dc['id']:<4}  {dc['host']}")
    print(f"    {C.CYAN}[5]{C.RESET}  All DCs")
    print(f"    {C.CYAN}[6]{C.RESET}  Select multiple — e.g. 1,3")
    choice = input("\n  Choice: ").strip()
    if choice == "5": return DCS[:]
    selected = []
    for part in choice.split(","):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(DCS): selected.append(DCS[idx])
        except ValueError: pass
    return selected if selected else select_dcs()

# ── operation menu ────────────────────────────────────────────────────────────
OPS = [
    ("1", "Reset password"),
    ("2", "Unlock account"),
    ("3", "Enable / Disable / Set description"),
    ("4", "Change group membership"),
    ("5", "Create new user"),
    ("6", "Look up user"),
    ("0", "Exit"),
]

def select_op():
    print(f"\n{C.BOLD}  Operation:{C.RESET}")
    for code, label in OPS:
        col = C.RED if code == "0" else C.CYAN
        print(f"    {col}[{code}]{C.RESET}  {label}")
    return input("\n  Choice: ").strip()

# ── main ──────────────────────────────────────────────────────────────────────
def prompt_credentials() -> tuple:
    """
    Prompt for AD credentials once at startup.
    Accepts NETBIOS format (NL\\firstname.lastname)
    or UPN format (firstname.lastname@nl.eu.com).
    """
    print(f"\n{C.BOLD}  Authentication{C.RESET}")
    print(f"  {C.DIM}Accepted formats:{C.RESET}")
    for dc in DCS:
        example_sam = "firstname.lastname"
        print(f"  {C.DIM}  {dc['id']:<4}  "
              f"{fmt_logon(dc, example_sam):<30}  "
              f"or  {fmt_upn(dc, example_sam)}{C.RESET}")
    print()
    user = input("  Username: ").strip()
    if not user:
        err("Username required")
        sys.exit(1)
    pwd = getpass.getpass("  Password: ")
    if not pwd:
        err("Password required")
        sys.exit(1)
    return user, pwd


def test_connections(dcs: list, user: str, pwd: str) -> dict:
    """
    Test authentication against each DC before allowing any operations.
    Returns dict of {dc_id: connection | None}
    """
    print(f"\n{C.BOLD}  Testing connections...{C.RESET}\n")
    connections = {}
    for dc in dcs:
        conn = connect(dc, user, pwd)
        connections[dc["id"]] = conn
        # connect() already prints success/failure — no duplicate message needed

    ok_count   = sum(1 for c in connections.values() if c)
    fail_count = len(connections) - ok_count

    print(f"\n  {C.BOLD}Connection summary:{C.RESET}")
    print(f"  {C.GREEN}✓ {ok_count} connected{C.RESET}  "
          f"{(C.RED + f'✗ {fail_count} failed' + C.RESET) if fail_count else ''}")

    if ok_count == 0:
        err("No DCs reachable — check VPN and credentials.")
        sys.exit(1)

    return connections


def main():
    print(f"""
{C.BOLD}{C.MAGENTA}╔══════════════════════════════════════════════════╗
║   Planview AD Manager — Interactive CLI Tool     ║
║   Mac → Windows Active Directory via LDAP(S)     ║
╚══════════════════════════════════════════════════╝{C.RESET}
""")

    # ── Step 1: credentials ───────────────────────────────────────────────
    user, pwd = prompt_credentials()

    # ── Step 2: select DCs and test auth before doing anything ────────────
    print(f"\n{C.BOLD}  Which DCs do you want to work with this session?{C.RESET}")
    session_dcs = select_dcs()

    connections = test_connections(session_dcs, user, pwd)

    # Keep only reachable DCs for this session
    active_dcs = [dc for dc in session_dcs if connections.get(dc["id"])]

    if len(active_dcs) < len(session_dcs):
        skipped = [dc["id"] for dc in session_dcs if not connections.get(dc["id"])]
        warn(f"Skipping unreachable: {', '.join(skipped)}")

    print(f"\n{C.GREEN}{C.BOLD}  ✓  Authenticated. Ready to perform operations on: "
          f"{', '.join(dc['id'] for dc in active_dcs)}{C.RESET}")

    # ── Step 3: operation loop ────────────────────────────────────────────
    while True:
        # Allow switching to a different DC subset within the session
        print(f"\n  {C.DIM}Active DCs: {', '.join(dc['id'] for dc in active_dcs)}")
        print(f"  Type 's' to switch DCs, or pick an operation below.{C.RESET}")

        op = select_op()

        if op == "0":
            print(f"\n  {C.DIM}Closing connections...{C.RESET}")
            for conn in connections.values():
                try:
                    if conn: conn.unbind()
                except Exception:
                    pass
            print(f"  {C.DIM}Goodbye.{C.RESET}\n")
            break

        if op == "s":
            # Re-select DCs within the same session (reuse existing connections)
            print(f"\n{C.BOLD}  Select DCs for next operation:{C.RESET}")
            new_selection = select_dcs()
            # Connect to any newly selected DCs not yet in session
            for dc in new_selection:
                if dc["id"] not in connections:
                    conn = connect(dc, user, pwd)
                    connections[dc["id"]] = conn
            active_dcs = [dc for dc in new_selection if connections.get(dc["id"])]
            if not active_dcs:
                err("None of the selected DCs are reachable")
            else:
                ok(f"Now targeting: {', '.join(dc['id'] for dc in active_dcs)}")
            continue

        if op not in [c for c, _ in OPS[:-1]]:
            warn("Invalid choice")
            continue

        for dc in active_dcs:
            print(f"\n{C.BOLD}{C.BLUE}  ── {dc['id']} ({dc['host']}) ──{C.RESET}")
            conn = connections.get(dc["id"])
            if not conn:
                warn(f"No active connection to {dc['id']} — skipping")
                continue
            try:
                if   op == "1": op_reset_password(conn, dc["base_dn"], dc["id"])
                elif op == "2": op_unlock(conn, dc["base_dn"], dc["id"])
                elif op == "3": op_permissions(conn, dc["base_dn"], dc["id"])
                elif op == "4": op_groups(conn, dc["base_dn"], dc["id"])
                elif op == "5": op_create_user(conn, dc["base_dn"], dc["id"])
                elif op == "6": op_lookup(conn, dc["base_dn"], dc["id"])
            except KeyboardInterrupt:
                warn("Interrupted")
            except ADOperationError as e:
                err(f"Operation failed on {dc['id']}: {e}")
                err(f"No changes were made on {dc['id']}.")
                if DEBUG: traceback.print_exc()
            except Exception as e:
                err(f"Unexpected error on {dc['id']}: {e}")
                if DEBUG: traceback.print_exc()

        if len(active_dcs) > 1:
            print(f"\n{C.GREEN}{C.BOLD}  ✓  Done on {len(active_dcs)} DC(s){C.RESET}")

        if input(f"\n  {C.DIM}Another operation? [Y/n]: {C.RESET}").strip().lower() == "n":
            print(f"\n  {C.DIM}Closing connections...{C.RESET}")
            for conn in connections.values():
                try:
                    if conn: conn.unbind()
                except Exception:
                    pass
            print(f"  {C.DIM}Goodbye.{C.RESET}\n")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.DIM}Bye.{C.RESET}\n")
        sys.exit(0)
