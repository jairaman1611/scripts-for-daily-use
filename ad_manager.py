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
DCS = [
    {"id":"UK", "host":"uk1-dc10.eu.uk.com",  "base_dn":"DC=eu,DC=uk,DC=com"},
    {"id":"NL", "host":"nl1-dc01.eu.nl.com",  "base_dn":"DC=eu,DC=nl,DC=com"},
    {"id":"SV", "host":"sv1-dc01.sv.zen.com", "base_dn":"DC=sv,DC=zen,DC=com"},
    {"id":"NJ", "host":"nj1-dc01.nj.zen.com", "base_dn":"DC=nj,DC=zen,DC=com"},
]

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
    except Exception as e:
        err(str(e))
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
    except Exception as e:
        err(str(e))
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

    default_sam = f"{first[0].lower()}{last.lower()}"
    sam   = input(f"  Username [{default_sam}]: ").strip() or default_sam
    domain= base_dn.replace("DC=","").replace(",",".")
    upn   = input(f"  UPN [{sam}@{domain}]: ").strip() or f"{sam}@{domain}"
    email = input(f"  Email [{upn}]: ").strip() or upn
    title = input("  Title (optional): ").strip()
    dept  = input("  Department (optional): ").strip()

    print(f"\n  OU:  {C.CYAN}[1]{C.RESET} CN=Users (default)   {C.CYAN}[2]{C.RESET} Custom path")
    ou_c  = input("  Choice [1]: ").strip()
    if ou_c == "2":
        ou  = input("  OU path (e.g. OU=IT,OU=Staff): ").strip()
        udn = f"CN={first} {last},{ou},{base_dn}"
    else:
        udn = f"CN={first} {last},CN=Users,{base_dn}"

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
    print(f"\n  {C.BOLD}Summary:{C.RESET}")
    print(f"  {'Name':<18} {first} {last}")
    print(f"  {'Username':<18} {sam}")
    print(f"  {'UPN':<18} {upn}")
    print(f"  {'DN':<18} {udn}")
    if cloned_dns:   print(f"  {'Cloned groups':<18} {len(cloned_dns)} group(s)")
    if manual_names: print(f"  {'Manual groups':<18} {', '.join(manual_names)}")
    if not cloned_dns and not manual_names:
        print(f"  {'Groups':<18} None")

    if not confirm(f"Create user on {dc_id}?"): return

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
    except Exception as e:
        err(str(e))
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
def main():
    print(f"""
{C.BOLD}{C.MAGENTA}╔══════════════════════════════════════════════════╗
║   Planview AD Manager — Interactive CLI Tool     ║
║   Mac → Windows Active Directory via LDAP(S)     ║
╚══════════════════════════════════════════════════╝{C.RESET}
""")
    shared = input("  Same credentials for all DCs? [Y/n]: ").strip().lower() != "n"
    creds = {}
    if shared:
        creds["user"] = input("  Username (DOMAIN\\\\user or user@domain): ").strip()
        creds["pwd"]  = getpass.getpass("  Password: ")

    while True:
        dcs = select_dcs()
        op  = select_op()
        if op == "0":
            print(f"\n  {C.DIM}Goodbye.{C.RESET}\n"); break
        if op not in [c for c,_ in OPS[:-1]]:
            warn("Invalid choice"); continue

        for dc in dcs:
            print(f"\n{C.BOLD}{C.BLUE}  ── {dc['id']} ({dc['host']}) ──{C.RESET}")
            if not shared:
                creds["user"] = input(f"  Username for {dc['id']}: ").strip()
                creds["pwd"]  = getpass.getpass("  Password: ")
            conn = connect(dc, creds["user"], creds["pwd"])
            if not conn: continue
            try:
                if   op=="1": op_reset_password(conn, dc["base_dn"], dc["id"])
                elif op=="2": op_unlock(conn, dc["base_dn"], dc["id"])
                elif op=="3": op_permissions(conn, dc["base_dn"], dc["id"])
                elif op=="4": op_groups(conn, dc["base_dn"], dc["id"])
                elif op=="5": op_create_user(conn, dc["base_dn"], dc["id"])
                elif op=="6": op_lookup(conn, dc["base_dn"], dc["id"])
            except KeyboardInterrupt:
                warn("Interrupted")
            except Exception as e:
                err(f"Unexpected error: {e}")
                if DEBUG: traceback.print_exc()
            finally:
                try: conn.unbind()
                except: pass

        if len(dcs) > 1:
            print(f"\n{C.GREEN}{C.BOLD}  ✓  Done on {len(dcs)} DC(s){C.RESET}")

        if input(f"\n  {C.DIM}Another operation? [Y/n]: {C.RESET}").strip().lower() == "n":
            print(f"\n  {C.DIM}Goodbye.{C.RESET}\n"); break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.DIM}Bye.{C.RESET}\n")
        sys.exit(0)
