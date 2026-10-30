"""Explanation quality of the curated finding rules.

Every finding is explained without AI (title, why, fix, refs), so these fields are part of the rule's
contract: a rule that a person cannot understand from its own text is a bug.
"""
from collections import Counter

import yaml

from containerizer.rules import RULES_DIR, load_rules

SERIOUS = {"refactor", "rewrite", "blocker"}
MIN_WHY = 60

# Refactor+ rules with no reference: no page was found that directly and verifiably backs the claim,
# so `why` and `fix` must stand on their own. Remove an id here once it gets a verified ref.
NO_VERIFIED_REF = {
    # 10-runtime
    "linq-to-sql": "no Microsoft page states LINQ to SQL's absence from modern .NET",
    # 20-platform
    "pinvoke-gui": "user32/gdi32/wtsapi32 are Windows system DLLs; no page covers them as a group",
    "process-start-exe": "depends on which tool is launched; nothing generic to link",
    "serial-port": "about hardware being out of the pod's reach, not an OS limitation (System.IO.Ports works on Linux)",
    "hardware-sdk": "device and driver specific; nothing generic to link",
    "vendor-sdk-install-dir": "vendor specific; the fix is to check that vendor's Linux support",
    # 30-integration
    "oledb-odbc-access": "System.Data.OleDb docs and package page carry no platform statement",
    # 35-config-os
    "os-drive-letters": "DriveInfo docs do not describe drive-letter behaviour on Linux",
    # 35-migration
    "mig-javascriptserializer": "no page found stating System.Web.Extensions is absent from modern .NET",
    "mig-enterprise-library": "retirement of Enterprise Library is not documented on a stable page",
    "mig-vb-compatibility": "no page found for the VB6 compatibility libraries on modern .NET",
    # 35-vendor-packages
    "pkg-mmi-cim": "Microsoft.Management.Infrastructure docs carry no platform statement",
    "pkg-informix": "IBM's Informix client SDK pages could not be verified",
    "pkg-tesseract-native": "package contents (Windows-only native builds) are shown by the package, not a doc page",
}


def curated_finding_rules():
    return [r for r in load_rules()
            if r.phase == "finding" and not r.file.startswith("rules/learned/")]


def test_no_duplicate_ids_across_curated_files():
    # load_rules() silently lets later files override earlier ids, so count the raw files
    ids = Counter()
    for f in sorted(RULES_DIR.glob("*.yaml")):
        for item in (yaml.safe_load(f.read_text()) or {}).get("rules", []) or []:
            if item.get("phase", "finding") == "finding":
                ids[item["id"]] += 1
    assert not [i for i, n in ids.items() if n > 1]


def test_every_finding_rule_explains_itself():
    bad = []
    for r in curated_finding_rules():
        why = " ".join(r.why.split())
        if not r.title.strip():
            bad.append(f"{r.id}: empty title")
        if len(why) < MIN_WHY:
            bad.append(f"{r.id}: why shorter than {MIN_WHY} characters ({len(why)})")
        if not r.fix.strip():
            bad.append(f"{r.id}: empty fix")
        for u in r.refs:
            if not (isinstance(u, str) and u.startswith("https://") and " " not in u):
                bad.append(f"{r.id}: ref is not an https URL: {u!r}")
    assert not bad, "\n".join(bad)


def test_serious_rules_have_a_reference():
    missing = [f"{r.id} ({r.file}, {r.severity})" for r in curated_finding_rules()
               if r.severity in SERIOUS and not r.refs and r.id not in NO_VERIFIED_REF]
    assert not missing, "add a verified ref, or list the rule in NO_VERIFIED_REF with a reason:\n" + "\n".join(missing)


def test_allowlist_names_existing_rules_with_reasons():
    known = {r.id for r in curated_finding_rules()}
    assert not set(NO_VERIFIED_REF) - known
    assert all(reason.strip() for reason in NO_VERIFIED_REF.values())
