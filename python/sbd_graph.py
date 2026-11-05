#!/usr/bin/env python3
"""ALSO Secure by Default - Microsoft Graph-only engine (cross-platform).

Covers the checks/settings that are pure Microsoft Graph: Entra user settings,
consent, FIDO2/auth methods, Entra LAPS / local admin and Intune MDM enrollment.
Exchange Online (audit log, Defender for Office 365) and SharePoint Online have no
Python SDK, so use scripts/Invoke-SecureByDefault.ps1 for those.

    python sbd_graph.py                      # Discover (read-only)
    python sbd_graph.py --mode enforce       # asks before each change
    python sbd_graph.py --mode enforce --yes # no prompts (CI)
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import requests
from azure.identity import InteractiveBrowserCredential

G = "https://graph.microsoft.com"
REF = json.loads((Path(__file__).parent.parent / "config" / "reference-state.json").read_text("utf-8"))
RESULTS = []
COLORS = {"Compliant": "32", "Fixed": "32", "Drift": "33", "Manual": "36", "Info": "37", "Error": "31"}

READ = ["Policy.Read.All", "Directory.Read.All", "DeviceManagementServiceConfig.Read.All"]
WRITE = ["Policy.ReadWrite.AuthorizationPolicy", "Policy.ReadWrite.AuthenticationMethod",
         "Policy.ReadWrite.ConsentRequest", "Policy.ReadWrite.PermissionGrant",
         "Policy.ReadWrite.DeviceConfiguration", "DeviceManagementServiceConfig.ReadWrite.All",
         "Directory.Read.All"]


class Graph:
    def __init__(self, scopes):
        self.cred = InteractiveBrowserCredential()
        self.scopes = [f"{G}/{s}" for s in scopes]

    def call(self, method, path, body=None):
        token = self.cred.get_token(*self.scopes).token
        r = requests.request(method, f"{G}{path}", json=body, timeout=60,
                             headers={"Authorization": f"Bearer {token}"})
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path}: {r.status_code} {r.text[:300]}")
        return r.json() if r.content else {}


def add(step, setting, current, expected, status, link=None):
    RESULTS.append(dict(Step=step, Setting=setting, Current=str(current), Expected=str(expected),
                        Status=status, Link=link))
    print(f"  \033[{COLORS[status]}m[{status:<9}]\033[0m {setting}: {current} (expected {expected})")
    if link and status in ("Manual", "Drift"):
        print(f"              -> {link}")


def compare(args, step, setting, current, expected, fix=None, link=None):
    if str(current) == str(expected):
        return add(step, setting, current, expected, "Compliant", link)
    if fix and args.mode == "enforce" and (args.yes or input(f"   Apply: {setting} -> {expected} ? [y/N] ").lower() in ("y", "yes")):
        try:
            fix()
            return add(step, setting, current, expected, "Fixed", link)
        except Exception as e:  # report and continue with next setting
            print(f"   ! {e}", file=sys.stderr)
            return add(step, setting, current, expected, "Error", link)
    add(step, setting, current, expected, "Drift", link)


def step_user_settings(g, a):
    u, ap = REF["userSettings"], "/v1.0/policies/authorizationPolicy"
    p = g.call("GET", ap)
    d = p["defaultUserRolePermissions"]
    link = "https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings"
    patch = lambda body: (lambda: g.call("PATCH", ap, body))
    compare(a, "UserSettings", "Users can register applications", d["allowedToCreateApps"], u["usersCanRegisterApps"],
            patch({"defaultUserRolePermissions": {"allowedToCreateApps": u["usersCanRegisterApps"]}}), link)
    compare(a, "UserSettings", "Restrict non-admin users from creating tenants", not d["allowedToCreateTenants"], u["restrictTenantCreation"],
            patch({"defaultUserRolePermissions": {"allowedToCreateTenants": not u["restrictTenantCreation"]}}), link)
    compare(a, "UserSettings", "Users can create security groups", d["allowedToCreateSecurityGroups"], u["usersCanCreateSecurityGroups"],
            patch({"defaultUserRolePermissions": {"allowedToCreateSecurityGroups": u["usersCanCreateSecurityGroups"]}}), link)
    compare(a, "UserSettings", "Guest user access (guestUserRoleId)", p["guestUserRoleId"], u["guestUserRoleId"],
            patch({"guestUserRoleId": u["guestUserRoleId"]}), "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AllowlistPolicyBlade")
    add("UserSettings", "Restrict access to Entra admin center / keep signed in / LinkedIn", "portal-only", "see reference", "Manual", link)


def step_consent(g, a):
    c, ap = REF["consent"], "/v1.0/policies/authorizationPolicy"
    p = g.call("GET", ap)
    cur = ",".join(p["defaultUserRolePermissions"].get("permissionGrantPoliciesAssigned", []))
    compare(a, "Consent", "User consent policy", cur, c["userConsentPolicy"],
            lambda: g.call("PATCH", ap, {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": [c["userConsentPolicy"]]}}),
            "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings")
    w = g.call("GET", "/v1.0/policies/adminConsentRequestPolicy")
    add("Consent", "Admin consent request workflow enabled", w.get("isEnabled"), True,
        "Compliant" if w.get("isEnabled") else "Drift",
        "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings")


def step_fido2(g, a):
    uri = "/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2"
    f = g.call("GET", uri)
    compare(a, "Fido2", "FIDO2 state", f["state"], "enabled",
            lambda: g.call("PATCH", uri, {"@odata.type": "#microsoft.graph.fido2AuthenticationMethodConfiguration", "state": "enabled",
                                          "includeTargets": [{"targetType": "group", "id": "all_users", "isRegistrationRequired": False}]}),
            "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods")


def step_auth_methods(g, a):
    pol = g.call("GET", "/v1.0/policies/authenticationMethodsPolicy")
    for m in pol["authenticationMethodConfigurations"]:
        weak = m["id"] in ("Sms", "Voice", "Email")
        add("AuthMethods", m["id"], m["state"], "disabled/limited" if weak else "review targets",
            "Drift" if weak and m["state"] == "enabled" else "Info")


def step_laps(g, a):
    uri = "/beta/policies/deviceRegistrationPolicy"
    dr = g.call("GET", uri)
    link = "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings"
    compare(a, "Laps", "Entra LAPS enabled", dr.get("localAdminPassword", {}).get("isEnabled"), True,
            lambda: g.call("PATCH", uri, {"localAdminPassword": {"isEnabled": True}}), link)
    compare(a, "Laps", "Global admins added as local admin on join", dr["azureADJoin"]["localAdmins"]["enableGlobalAdmins"], False,
            lambda: g.call("PATCH", uri, {"azureADJoin": {"localAdmins": {"enableGlobalAdmins": False}}}), link)
    add("Laps", "Windows LAPS policy deployment", "manual", "deployed via Intune", "Manual")


def step_intune(g, a):
    base = "/beta/policies/mobileDeviceManagementPolicies"
    pols = [p for p in g.call("GET", base)["value"] if "Intune" in p.get("displayName", "")]
    if not pols:
        return add("IntuneEnrollment", "MDM policy", "not found", "Intune", "Manual")
    p = pols[0]
    compare(a, "IntuneEnrollment", "MDM user scope", p["appliesTo"], "all",
            lambda: g.call("PATCH", f"{base}/{p['id']}", {"appliesTo": "all"}),
            "https://intune.microsoft.com/#view/Microsoft_AAD_IAM/MdmConfiguration.ReactView")


STEPS = {"UserSettings": step_user_settings, "Consent": step_consent, "Fido2": step_fido2,
         "AuthMethods": step_auth_methods, "Laps": step_laps, "IntuneEnrollment": step_intune}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["discover", "enforce"], default="discover")
    ap.add_argument("--steps", nargs="+", choices=list(STEPS), default=list(STEPS))
    ap.add_argument("--yes", action="store_true", help="do not prompt per change")
    ap.add_argument("--output", default="sbd-reports")
    a = ap.parse_args()

    print(f"ALSO Secure by Default (Python) - mode: {a.mode}")
    g = Graph(WRITE if a.mode == "enforce" else READ)
    for s in a.steps:
        print(f"\n== {s} ==")
        try:
            STEPS[s](g, a)
        except Exception as e:
            add(s, "step execution", str(e)[:200], "success", "Error")
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=True)
    f = out / f"sbd-py-{a.mode}-{datetime.now():%Y%m%d-%H%M%S}.json"
    f.write_text(json.dumps(RESULTS, indent=2), "utf-8")
    print(f"\nReport: {f}")


if __name__ == "__main__":
    main()
