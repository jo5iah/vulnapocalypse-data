"""Per-CVE stratification table, and the stratified exploitation rates built from it.

One row per CVE: publication date, vendor, product families, CVSS exposure fields, severity,
weakness types, CISA's SSVC decision points and the KEV addition date. Everything the model's
planned stratification needs (plan.md step 2, in vulnapocalypse-modeling) is a group-by over this table.

    python3 cve_strata.py build  --start 2025-11-16 --end 2026-11-16   # full sweep, ~1 h unkeyed
    python3 cve_strata.py update                                       # only what changed since
    python3 cve_strata.py retype                                       # reapply the ptype rules; no network
    python3 cve_strata.py report [--as-of 2026-11-16] [--window-days 365] [--top 20]

Files, all under data/ unless noted:

    cve_strata.csv.gz            the per-CVE table (gzip CSV, sorted by CVE id)
    cve_strata_meta.json         sweep floor, last sync time, row counts
    cve_stratification_<as-of>.csv   long-format cells: vendor x exposure -> counts
    cve_ptype_<as-of>.json       the product-type tables, as the data page's figures read them
    ../cve_stratification_<as-of>.md the tables a person reads

`update` asks NVD only for records modified since the last sync (lastModStartDate), which covers
new publications, CVEs that gained CPE applicability or a CVSS score since, and new KEV flags, so
keeping the table current costs minutes rather than a full sweep. The KEV catalog is refetched
whole on every build and update, and KEV CVEs published before the sweep floor are kept as rows
so that additions in a window can be classified whatever their publication date.

Set NVD_API_KEY to use NVD's keyed rate limit (50 requests / 30 s instead of 5).

Three things to know when reading any rate from this table:

  * Vendor comes from NVD's CPE applicability when the record has it, else from the `affected`
    block the CVE's assigner supplied, else it is empty. `vendor_source` records which. The two
    taxonomies are not identical; assigner names are normalized but not reconciled to CPE names.
  * A CVE that lists several vendors is assigned one, so the table is a partition: the vendor
    with the most vulnerable CPE entries, ignoring distributions that repackage upstream code
    (REPACKAGERS) whenever another vendor is present. `families` keeps every vendor:product.
  * Exposure is read from the CVSS vector, preferring NVD's own (Primary) score within the
    newest CVSS version present. Unscored records form their own class rather than being dropped.
  * Product type (`ptype`) is one of os, prodserver, client, edge, mgmt, other: PTYPE_RULES
    applied to the CVE's CPE families, one vote per vendor, with distributions and vendors that
    only embed the code set aside (see ptype()). Without CPE it comes from the vendor alone when
    that vendor ships one type (VENDOR_PTYPE), else it is empty; `ptype_source` records which.
    It is derived from the other columns and rewritten whenever the table is, so `retype` is
    all a rule change needs. `channel`, who assigned the CVE, is derived the same way.
  * `cpe_part` (a application, o operating system or firmware, h hardware) and `target_sw` (the
    platform a product runs on: wordpress, node.js, python ...) are NVD's own CPE fields for the
    vulnerable products. They are recorded, not inferred, and exist only where CPE does.
"""

import argparse
import csv
import datetime as dt
import gzip
import json
import math
import os
import re
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
TABLE = DATA / "cve_strata.csv.gz"
META = DATA / "cve_strata_meta.json"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEY = os.environ.get("NVD_API_KEY")
UA = {"User-Agent": "vulnapocalypse-research/1.0", **({"apiKey": KEY} if KEY else {})}
NVD_GAP, PAGE, MAX_RANGE = (0.7 if KEY else 6.6), 2000, 110
_last = [0.0]

FIELDS = ["cve", "published", "last_modified", "status", "source", "vendor", "vendor_source",
          "families", "cvss_version", "cvss_type", "base_score", "severity", "av", "pr", "ui",
          "exposure", "cwes", "ssvc_exploitation", "ssvc_automatable", "ssvc_impact", "kev_added",
          "cpe_part", "target_sw", "channel", "ptype", "ptype_source"]

REPACKAGERS = {"debian", "fedoraproject", "redhat", "canonical", "opensuse", "suse", "netapp",
               "gentoo", "almalinux", "rockylinux", "amazon"}
VERSIONISH = re.compile(r"^(\d+(\.\d+)*|\d+h\d+|r\d+|sp\d+|v\d+|\d+[a-z]?)$")
CORP = re.compile(r"\b(the|inc|incorporated|corporation|corp|co|company|llc|ltd|limited|gmbh|ag|"
                  r"sa|plc|bv|pty|oy|ab|kk|srl|technologies|technology|software foundation|"
                  r"foundation|project|team|systems?)\b\.?")
EXPOSURES = ["remote, no privileges, no user action", "remote, other", "local or physical",
             "unscored"]

# Product type. One label per CVE, from what the affected product is for:
#   os          operating systems and hypervisors (Windows, Linux kernel and distributions,
#               macOS, iOS, Android, ESXi)
#   prodserver  servers people do their work through: mail, collaboration and wikis, content
#               management, file transfer, ERP/CRM, source control and CI, help desk, telephony
#   client      software a person runs: browsers, office suites, readers, media, messaging, IDEs
#   edge        network-perimeter devices: firewalls, VPN and remote-access gateways, load
#               balancers, routers and switches, enterprise and consumer, with the consoles
#               their vendors sell to manage them
#   mgmt        software that administers other systems: remote management and support, endpoint
#               and mobile device management, virtualization management, backup, monitoring,
#               endpoint security, identity and privileged access, hosting control panels
#   other       everything else: middleware, databases, AI and workflow servers, libraries,
#               chipsets, IoT, NAS and industrial control
# Rules are tried in order against `vendor:product`; the first match wins, no match is `other`.
# Exceptions therefore sit above the rule they carve out of (Cisco's non-network products
# above the Cisco catch-all in `edge`).
PTYPES = ["os", "prodserver", "client", "edge", "mgmt", "other"]
PTYPE_NAME = {"os": "operating system", "prodserver": "productivity server",
              "client": "client / user app", "edge": "edge device",
              "mgmt": "infrastructure management", "other": "other"}
PTYPE_RULES = [(t, re.compile(rx)) for t, rx in [
    ("edge", r"^ivanti:(cloud_services_appliance|endpoint_manager_cloud_services)"),
    ("mgmt", r"^(cisco:(identity_services|data_center_network|prime|smart_licensing|dna"
             r"|digital_network|nexus_dashboard|crosswork|ucs|integrated_management"
             r"|application_policy|secure_access_control|intersight|hyperflex|duo"
             r"|common_services|network_services_orch|enterprise_nfv|evolved|thousandeyes"
             r"|appdynamics|cyber_vision)"
             r"|fortinet:forti(client|sandbox|siem|analyzer|soar|edr|portal|authenticator"
             r"|deceptor|ndr)|paloaltonetworks:(expedition|cortex|traps)"
             r"|checkpoint:(endpoint|zonealarm|harmony)"
             r"|sonicwall:(global_management|analytics)|juniper:(junos_space|contrail|paragon)"
             r"|ivanti:(endpoint_manager|avalanche|neurons_for_itsm|workspace_control|velocity"
             r"|patch|desktop|xtraction|application_control|automation))"),
    ("other", r"^(cisco:(ip_phone|broadworks|anyconnect|secure_client|webex|unified_contact"
              r"|unified_intelligence|packaged_contact|finesse|emergency|virtualized"
              r"|telepresence|jabber|industrial)"
              r"|fortinet:forti(recorder|camera|token|tester)"
              r"|sonicwall:(email_security|netextender)|ivanti:secure_access_client"
              r"|f5:nginx)"),
    ("prodserver", r"^cisco:(unified_communications|unity_connection|unified_presence"
                   r"|webex_meetings_server|expressway)"),
    ("prodserver", r"^accellion:(fta|kiteworks)"),
    ("edge", r"^(fortinet:|paloaltonetworks:|sonicwall:|pulsesecure:|zyxel:|arista:|mikrotik:"
             r"|draytek:|arraynetworks:|versa-networks:|netgear:|dlink:|tp-link:|tenda:"
             r"|totolink:|linksys:|ubiquiti:|ui:|trendnet:|edimax:|wavlink:|ruckuswireless:"
             r"|commscope:|pfsense:|netgate:|opnsense:|stormshield:|sangfor:|a10networks:"
             r"|riverbed:|silver-peak:|cradlepoint:|peplink:|sierrawireless:|teltonika"
             r"|four-faith:|comtrend:|dasannetworks:|netis-systems:|realtek:|dd-wrt:"
             r"|libraesva:|aviatrix:|fatpipeinc:|securepoint:|watchguard:|cisco:"
             r"|ivanti:(connect_secure|policy_secure|neurons_for_zta|cloud_services_appliance"
             r"|endpoint_manager_cloud_services|sentry|pulse|virtual_traffic)|mobileiron:sentry"
             r"|citrix:(netscaler|application_delivery|gateway|adc|sd-wan)"
             r"|f5:(big-ip|big-iq|f5os|traffix)|checkpoint:|juniper:"
             r"|sophos:(sfos|xg_|firewall|utm|cyberoam|web_appliance)"
             r"|barracuda:|arubanetworks:(arubaos|instant|clearpass|sd-wan|edgeconnect)"
             r"|hpe:(aruba|instant)|asus:.*(rt-|router|firmware)|zte:"
             r"|huawei:.*(router|firewall|usg|ar\d|hg\d)|progress:loadmaster|kemptechnologies:"
             r"|forcepoint:.*(firewall|ngfw|vpn)|openvpn:access|symantec:messaging_gateway"
             r"|microsoft:forefront_threat)"),
    ("os", r"^(microsoft:(windows|win32k|server_message_block|hyper-v)|linux:linux_kernel"
           r"|apple:(macos|mac_os|iphone_os|ipados|watchos|tvos|visionos)|google:android"
           r"|android:|samsung:(android|mobile)|debian:|canonical:|redhat:enterprise_linux"
           r"|fedoraproject:|suse:linux|opensuse:|oracle:(linux|solaris)|freebsd:"
           r"|openbsd:openbsd|netbsd:|ibm:(aix|vios|i$|z\/os)|huawei:(harmonyos|emui)"
           r"|vmware:(esxi|workstation|fusion)|xen:|qemu:|igel:igel_os"
           r"|sudo_project:|polkit_project:|gnu:(glibc|bash)|libuser_project:"
           r"|systemd_project:|linux-pam:|kernel:(util-linux|linux-pam))"),
    ("prodserver", r"^(microsoft:(sharepoint|exchange|office_online_server|office_web_apps"
                   r"|project_server|skype_for_business_server|lync_server|dynamics|biztalk)"
                   r"|synacor:|zimbra:|atlassian:|roundcube:|smartertools:|icewarp:|mdaemon:"
                   r"|mailenable:|exim:|postfix:|dovecot:|squirrelmail:|horde:|open-xchange:"
                   r"|nextcloud:|owncloud:|alfresco:|mattermost:|rocket\.chat:|discourse:"
                   r"|gitlab:|gitea:|gogs:|github:enterprise|jetbrains:(teamcity|youtrack|hub)"
                   r"|jenkins:jenkins|sonatype:|jfrog:|sap:|apache:ofbiz"
                   r"|oracle:(e-business|peoplesoft|siebel|jd_edwards|hyperion|webcenter|agile"
                   r"|business_intelligence|bi_publisher)|3ds:|dassault"
                   r"|progress:(moveit|ws_ftp|sitefinity|telerik)|crushftp:|cleo:|fortra:"
                   r"|kiteworks:|gladinet:|solarwinds:(serv-u|web_help_desk)|wftpserver:|rejetto:"
                   r"|citrix:(sharefile|xenapp|virtual_apps|workspace|storefront|xenmobile)"
                   r"|vmware:(horizon|workspace_one)|wordpress:wordpress|drupal:|joomla:"
                   r"|craftcms:|sitecore:|kentico:|dotnetnuke|dnnsoftware:|dotcms:|octobercms:"
                   r"|liferay:|concretecms:|adobe:(experience_manager|commerce|magento|connect)"
                   r"|magento:|zohocorp:manageengine_(servicedesk|supportcenter)|sysaid:"
                   r"|zammad:|glpi-project:|vbulletin:|phpbb:|mediawiki:|dokuwiki:|xwiki:"
                   r"|redmine:|mantisbt:|openproject:|moodle:|chamilo:|sangoma:|freepbx:"
                   r"|mitel:|3cx:|avaya:|trueconf:|onlyoffice:|collabora"
                   r"|ibm:(domino|lotus_domino|websphere_portal|connections|maximo|cognos"
                   r"|filenet|sterling)|hcltech:domino|openemr:|open-emr:|odoo:|sugarcrm:"
                   r"|suitecrm:|vtiger:|servicenow:)"),
    ("client", r"^(google:(chrome|v8|dawn|angle|skia)|mozilla:"
               r"|microsoft:(internet_explorer|edge|office|365_apps|word|excel|powerpoint"
               r"|outlook|onenote|access|publisher|visio|project$|teams|skype|onedrive"
               r"|silverlight|works|open_xml|windows_media|xml_core|msxml|jscript|vbscript"
               r"|chakra|visual_studio_code|remote_desktop$)"
               r"|apple:(safari|itunes|quicktime|webkit|icloud|xcode|garageband|pages|numbers"
               r"|keynote|music)|webkitgtk:|wpewebkit:"
               r"|adobe:(acrobat|reader|flash|air|shockwave|photoshop|illustrator|indesign"
               r"|premiere|after_effects|bridge|animate|dreamweaver|framemaker|substance"
               r"|lightroom|media_encoder|incopy|digital_editions|dimension|audition|creative)"
               r"|foxit:|oracle:(jre|jdk|java_se|vm_virtualbox|openoffice|graalvm)|sun:(jre|jdk)"
               r"|libreoffice:|apache:openoffice|kingsoft:|rarlab:|7-zip:|winzip:|videolan:"
               r"|zoom:|slack:|whatsapp:|telegram|signal:|discord|opera:|brave:"
               r"|realnetworks:|irfanview|gimp:|wireshark:|putty:|notepad|vim:"
               r"|jetbrains:(intellij|pycharm|rider|webstorm|phpstorm|goland|clion)"
               r"|teamviewer:|anydesk:|freerdp:|openclaw:|b3log:siyuan|telemessage:"
               r"|disc-soft:)"),
    ("mgmt", r"^(ivanti:|mobileiron:|zohocorp:|connectwise:|n-able:|simple-help:|kaseya:"
             r"|beyondtrust:|solarwinds:|veeam:|veritas:|commvault:|acronis:|arcserve:|ahsay:"
             r"|nakivo:|nagios:|zabbix:|paessler:|progress:whatsup|trendmicro:|mcafee:"
             r"|trellix:|symantec:|sophos:|kaspersky:|eset:|bitdefender:|crowdstrike:"
             r"|sentinelone:|tanium:|quest:|netwrix:|saltstack:|puppet:|papercut:"
             r"|devolutions:|cyberark:|forgerock:|wazuh:|checkmk:|tenable:|rapid7:"
             r"|eyesofnetwork:|rconfig:|absolute:|fleetdm:|hashicorp:|librenms:|cacti:"
             r"|gfi:|motex:|skygroup:|teamt5:|sciencelogic:|control-webpanel:|cyberpanel:"
             r"|webmin:|cpanel:|litespeedtech:|plesk:"
             r"|vmware:(vcenter|cloud_foundation|aria|vrealize|vsphere|identity_manager"
             r"|one_access|nsx|tools|telco_cloud|carbon_black|site_recovery)"
             r"|broadcom:vmware_(vcenter|aria|nsx|cloud)"
             r"|microsoft:(defender|malware_protection|configuration_manager|system_center"
             r"|open_management|azure_automation|endpoint_protection|security_essentials"
             r"|intune|windows_admin_center)"
             r"|hp:(openview|system_management|systems_insight|insight|procurve_manager"
             r"|oneview|version_control|matrix_operating)"
             r"|hpe:(oneview|intelligent_management|systems_insight)"
             r"|dell:(openmanage|idrac|emc_networker|networker|avamar|recoverpoint"
             r"|powerprotect|wyse_management|secure_connect)"
             r"|ibm:(tivoli|bigfix|spectrum_protect|qradar)|hcltech:bigfix"
             r"|microfocus:(operations|access_manager|netiq)|redhat:(ansible|satellite))"),
]]
PTYPE_TIE = ["edge", "prodserver", "client", "os", "mgmt", "other"]   # equal votes: this order
# A CVE in shared code lists everyone who ships it. Distributions repackage it, suites bundle
# it, and devices and management products embed it; none of them is what the flaw is in.
DISTRO_FAMILY = re.compile(r"^(debian:|fedoraproject:|canonical:|opensuse:|suse:|gentoo:"
                           r"|almalinux:|rockylinux:|centos:|netapp:|redhat:enterprise_linux"
                           r"|novell:(suse|opensuse)|oracle:(linux|solaris)|amazon:linux)")
BUNDLE_FAMILY = re.compile(r"^vmware:(cloud_foundation|telco_cloud)")
EMBEDDERS = ["other", "edge", "mgmt"]         # dropped in this order while another type remains
# Assigner-named vendors (no CPE yet) that ship one product type. Spelled as norm_vendor() leaves
# them. Vendors that ship several types stay untyped; `report` spreads them over the types in
# proportion to that vendor's typed CVEs.
VENDOR_PTYPE = {
    **{v: "os" for v in "linux xen samsung_mobile freebsd".split()},
    **{v: "edge" for v in ("totolink tenda d_link tp_link edimax draytek trendnet wavlink netcore "
                           "juniper_networks fortinet arista_networks watchguard ubiquiti zyxel "
                           "sonicwall netgear linksys mikrotik palo_alto_networks check_point "
                           "f5 ruckus_wireless h3c utt comfast lb_link ruijie").split()},
    **{v: "client" for v in "mozilla openclaw siyuan_note foxit zoom".split()},
    **{v: "prodserver" for v in ("drupal gitea craftcms sap_se openemr typo3 wikimedia tryghost "
                                 "frappe mattermost discourse gitlab atlassian getgrav jenkins "
                                 "yeswiki").split()},
    **{v: "mgmt" for v in ("zohocorp tanium trend_micro veeam acronis connectwise n_able "
                           "beyondtrust commvault nagios zabbix").split()},
}
# Who assigned the CVE, from NVD's sourceIdentifier. Recorded for every record, CPE or not.
CHANNELS = ["GitHub advisory", "WordPress CNA", "VulDB", "VulnCheck", "MITRE",
            "CISA or national CERT", "research or bounty CNA", "vendor or project CNA"]
CHANNEL_RULES = [(c, re.compile(rx)) for c, rx in [
    ("GitHub advisory", r"^security-advisories@github\.com$"),
    ("WordPress CNA", r"@(patchstack|wordfence|wpscan)\.com$"),
    ("VulDB", r"@vuldb\.com$"), ("VulnCheck", r"@vulncheck\.com$"),
    ("MITRE", r"^cve@mitre\.org$"),
    ("CISA or national CERT", r"(cert|csirt|ncsc|cisa|dhs\.gov|usom\.gov|incibe|tech\.gov\.sg"
                              r"|cyber\.gov|govcert|\.gov\.)"),
    ("research or bounty CNA", r"(zdi-disclosures@|huntr|snyk\.io|hackerone\.com|talos-cna@"
                               r"|fluidattacks|vuln@|research@|@checkmarx|@jfrog\.com$)"),
]]
# Releases NVD files under separate products but that are one thing to an attacker; used only
# for the per-family table of the report.
FAMILY_GROUPS = [(re.compile(rx), name) for rx, name in [
    (r"^microsoft:sharepoint", "microsoft:sharepoint*"),
    (r"^microsoft:windows", "microsoft:windows*"),
    (r"^microsoft:(office|365_apps|word|excel|powerpoint|outlook)", "microsoft:office*"),
    (r"^citrix:(netscaler|application_delivery|gateway|adc)", "citrix:netscaler*"),
    (r"^f5:big-ip", "f5:big-ip*"),
    (r"^(ivanti:(connect_secure|policy_secure|pulse|neurons_for_zta)|pulsesecure:)",
     "ivanti:connect_secure*"),
    (r"^cisco:(adaptive_security|secure_firewall|firepower)", "cisco:asa_ftd*"),
    (r"^cisco:ios(_xe)?$", "cisco:ios*"),
    (r"^cisco:(catalyst_sd-wan|sd-wan)", "cisco:sd-wan*"),
    (r"^fortinet:forti(os|proxy)$", "fortinet:fortios*"),
    (r"^sonicwall:sma", "sonicwall:sma*"),
    (r"^atlassian:confluence", "atlassian:confluence*"),
    (r"^adobe:(acrobat|reader)", "adobe:acrobat*"),
    (r"^adobe:(commerce|magento)", "adobe:commerce*"),
    (r"^apple:(iphone_os|ipados)$", "apple:ios*"),
    (r"^apple:(macos|mac_os_x)$", "apple:macos*"),
    (r"^zyxel:", "zyxel:firmware*"), (r"^papercut:", "papercut:ng_mf*"),
    (r"^checkpoint:(gaia|quantum|multi-domain)", "checkpoint:gaia_quantum*"),
]]
KEV_OPENED = "2021-11-03"


def get(url, retries=5):
    for attempt in range(retries):
        wait = NVD_GAP - (time.time() - _last[0])
        if wait > 0:
            time.sleep(wait)
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=240) as r:
                payload = json.loads(r.read())
            _last[0] = time.time()
            return payload
        except Exception as exc:                                    # noqa: BLE001
            print(f"    retry {attempt + 1}/{retries}: {type(exc).__name__} "
                  f"{getattr(exc, 'code', '')}", flush=True)
            _last[0] = time.time()
            time.sleep(20)
    raise RuntimeError(f"could not fetch {url}")


def pages(flags=(), **params):
    """Every record matching an NVD query, one page at a time."""
    index, total = 0, None
    while total is None or index < total:
        url = NVD + "?" + urllib.parse.urlencode(
            {**params, "resultsPerPage": PAGE, "startIndex": index}, safe=":")
        for flag in flags:
            url += f"&{flag}"
        payload = get(url)
        total = payload["totalResults"]
        index += PAGE
        yield payload["vulnerabilities"], min(index, total), total


def family(vendor, product):
    """CPE gives each release its own product; strip trailing version tokens to get the family."""
    toks = product.split("_")
    while len(toks) > 1 and VERSIONISH.match(toks[-1]):
        toks.pop()
    return f"{vendor}:{'_'.join(toks)}"


def norm_vendor(name):
    """Assigner-supplied vendor text to a CPE-like token: 'Microsoft Corporation' -> 'microsoft'."""
    s = CORP.sub(" ", name.lower().replace(",", " "))
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s if s not in ("", "n_a", "na", "unknown", "none") else ""


def cpe_vendors(cve):
    """Vendors, product families, CPE parts and target software of the vulnerable products."""
    counts, fams, kinds, sw = Counter(), set(), set(), set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = re.split(r"(?<!\\):", match.get("criteria", ""))   # '\:' is a literal colon
                if match.get("vulnerable") and len(parts) > 4:
                    counts[parts[3]] += 1
                    fams.add(family(parts[3], parts[4]))
                    kinds.add(parts[2])
                    if len(parts) > 10 and parts[10] not in ("*", "-"):
                        sw.add(parts[10])
    return counts, fams, kinds, sw


def pick_vendor(counts):
    """One vendor per CVE. Repackaging distributions lose to any other vendor present."""
    own = {v: n for v, n in counts.items() if v not in REPACKAGERS} or dict(counts)
    return max(own, key=lambda v: (own[v], v)) if own else ""


def cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        m = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        d = m["cvssData"]
        av = (d.get("attackVector") or d.get("accessVector") or "").upper()
        pr = (d.get("privilegesRequired") or d.get("authentication") or "").upper()
        ui = d.get("userInteraction")
        if ui is None and "userInteractionRequired" in m:          # CVSS v2 keeps it beside cvssData
            ui = "REQUIRED" if m["userInteractionRequired"] else "NONE"
        sev = d.get("baseSeverity") or m.get("baseSeverity") or ""
        return {"cvss_version": d.get("version", ""), "cvss_type": m.get("type", ""),
                "base_score": d.get("baseScore", ""), "severity": sev.upper(),
                "av": av, "pr": pr, "ui": (ui or "").upper()}
    return {"cvss_version": "", "cvss_type": "", "base_score": "", "severity": "",
            "av": "", "pr": "", "ui": ""}


def exposure(av, pr, ui):
    if not av:
        return EXPOSURES[3]
    if av in ("NETWORK", "ADJACENT_NETWORK", "ADJACENT"):
        return EXPOSURES[0] if pr == "NONE" and ui in ("NONE", "") else EXPOSURES[1]
    return EXPOSURES[2]


def ssvc(cve):
    out = {"ssvc_exploitation": "", "ssvc_automatable": "", "ssvc_impact": ""}
    for m in cve.get("metrics", {}).get("ssvcV203", []):
        for opt in m.get("ssvcData", {}).get("options", []):
            for k, v in opt.items():
                key = {"exploitation": "ssvc_exploitation", "automatable": "ssvc_automatable",
                       "technicalImpact": "ssvc_impact"}.get(k)
                if key:
                    out[key] = v
    return out


def family_ptype(fam):
    return next((t for t, rx in PTYPE_RULES if rx.search(fam)), "other")


def ptype(vendor, families):
    """(type, source) for one CVE.

    Each vendor listed gets one vote, for the commonest type among its families, so a device
    maker listing thirty models counts once. Distributions and suites are left out while anything
    else is listed. When several vendors remain the flaw is in shared code, and the vendors
    that embed it (EMBEDDERS) are dropped while another type remains: a kernel flaw that F5 also
    ships is an operating-system flaw, and a Chrome flaw that Couchbase also ships is a client one.
    """
    fams = families.split("|") if families else []
    if not fams:
        return (VENDOR_PTYPE[vendor], "vendor") if vendor in VENDOR_PTYPE else ("", "")
    own = [f for f in fams if not DISTRO_FAMILY.search(f)] or fams
    by_vendor = defaultdict(list)
    for f in own:
        by_vendor[f.split(":")[0]].append(f)
    votes = Counter()
    for fs in by_vendor.values():
        fs = [f for f in fs if not BUNDLE_FAMILY.search(f)] or fs
        c = Counter(family_ptype(f) for f in fs)
        votes[max(c, key=lambda t: (c[t], -PTYPE_TIE.index(t)))] += 1
    if len(by_vendor) > 1:
        for t in EMBEDDERS:
            if len(votes) > 1:
                votes.pop(t, None)
    return max(votes, key=lambda t: (votes[t], -PTYPE_TIE.index(t))), "cpe"


def channel(source):
    return next((c for c, rx in CHANNEL_RULES if rx.search(source or "")), CHANNELS[-1])


def set_ptype(r):
    """The derived columns: product type and assignment channel."""
    r["ptype"], r["ptype_source"] = ptype(r["vendor"], r["families"])
    r["channel"] = channel(r.get("source", ""))
    return r


def row(cve):
    counts, fams, kinds, sw = cpe_vendors(cve)
    vendor, vsrc = pick_vendor(counts), "cpe"
    if not vendor:
        seen = Counter(norm_vendor(a.get("vendor") or "") for blk in cve.get("affected", [])
                       for a in blk.get("affectedData", []))
        seen.pop("", None)
        vendor, vsrc = (max(seen, key=lambda v: (seen[v], v)), "assigner") if seen else ("", "")
    c = cvss(cve)
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    return set_ptype({"cve": cve["id"], "published": cve["published"][:10],
            "last_modified": cve["lastModified"][:19], "status": cve.get("vulnStatus", ""),
            "source": cve.get("sourceIdentifier", ""), "vendor": vendor, "vendor_source": vsrc,
            "families": "|".join(sorted(fams)), **c,
            "exposure": exposure(c["av"], c["pr"], c["ui"]), "cwes": "|".join(cwes), **ssvc(cve),
            "kev_added": cve.get("cisaExploitAdd", ""),
            "cpe_part": "|".join(sorted(kinds)), "target_sw": "|".join(sorted(sw))})


def read_table():
    if not TABLE.exists():
        return {}
    with gzip.open(TABLE, "rt", newline="") as fh:
        return {r["cve"]: r for r in csv.DictReader(fh)}


def cve_key(cve_id):
    _, year, num = cve_id.split("-")
    return int(year), int(num)


def write_table(rows, meta):
    tmp = TABLE.with_suffix(".tmp")
    with gzip.open(tmp, "wt", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for cid in sorted(rows, key=cve_key):
            w.writerow({k: set_ptype(rows[cid]).get(k, "") for k in FIELDS})   # ptype is derived
    tmp.replace(TABLE)                       # a failed sweep never leaves a half-written table
    meta["rows"] = len(rows)
    meta["rows_kev"] = sum(1 for r in rows.values() if r["kev_added"])
    META.write_text(json.dumps(meta, indent=1))
    print(f"wrote {TABLE.relative_to(ROOT)}: {len(rows):,} rows, {meta['rows_kev']:,} in KEV")


def windows(start, end):
    while start <= end:
        stop = min(start + dt.timedelta(days=MAX_RANGE), end)
        yield start, stop
        start = stop + dt.timedelta(days=1)


def sweep_kev(rows):
    n = 0
    for vulns, done, total in pages(flags=("hasKev",)):
        for v in vulns:
            rows[v["cve"]["id"]] = row(v["cve"])
            n += 1
        print(f"  KEV {done:,}/{total:,}", flush=True)
    return n


def build(args):
    start, end = dt.date.fromisoformat(args.start), dt.date.fromisoformat(args.end)
    synced = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    rows = {} if args.fresh else read_table()
    for a, b in windows(start, end):
        for vulns, done, total in pages(pubStartDate=f"{a}T00:00:00.000",
                                        pubEndDate=f"{b}T23:59:59.999"):
            for v in vulns:
                rows[v["cve"]["id"]] = row(v["cve"])
            print(f"  published {a}..{b}  {done:>6,}/{total:<6,}  rows {len(rows):,}", flush=True)
    sweep_kev(rows)
    old = json.loads(META.read_text()) if META.exists() and not args.fresh else {}
    floor = min(str(start), old.get("floor", str(start)))
    write_table(rows, {"floor": floor, "last_sync": synced.isoformat(timespec="seconds"),
                       "source": NVD})


def update(args):
    meta = json.loads(META.read_text())
    rows = read_table()
    since = dt.datetime.fromisoformat(meta["last_sync"]) - dt.timedelta(hours=6)   # overlap
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    floor, changed, added = meta["floor"], 0, 0
    a = since
    while a < now:
        b = min(a + dt.timedelta(days=MAX_RANGE), now)
        for vulns, done, total in pages(lastModStartDate=a.isoformat(timespec="milliseconds"),
                                        lastModEndDate=b.isoformat(timespec="milliseconds")):
            for v in vulns:
                cve = v["cve"]
                if cve["published"][:10] < floor and cve["id"] not in rows:
                    continue                 # modified, but published before the table begins
                added += cve["id"] not in rows
                changed += 1
                rows[cve["id"]] = row(cve)
            print(f"  modified {a:%Y-%m-%d}..{b:%Y-%m-%d}  {done:>6,}/{total:<6,}", flush=True)
        a = b
    sweep_kev(rows)
    print(f"{changed:,} rows refreshed, {added:,} of them new")
    write_table(rows, {**meta, "last_sync": now.isoformat(timespec="seconds")})


def retype(args):
    """Reapply the product-type rules to the stored table. No network."""
    rows = read_table()
    before = Counter(r.get("ptype", "") for r in rows.values())
    write_table(rows, json.loads(META.read_text()))
    after = Counter(r["ptype"] for r in rows.values())
    for t in PTYPES + [""]:
        print(f"  {t or '(untyped)':<12}{before[t]:>8,} -> {after[t]:>8,}")


# ---------------------------------------------------------------------------- report

def poisson_interval(k, level=0.95):
    """Exact (Garwood) interval for a Poisson mean given a count of k."""
    def cdf(n, mu):
        term = total = math.exp(-mu)
        for i in range(1, n + 1):
            term *= mu / i
            total += term
        return total

    def solve(f):                            # f is decreasing in mu
        lo, hi = 0.0, 3.0 * k + 30
        for _ in range(60):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if f(mid) > 0 else (lo, mid)
        return (lo + hi) / 2
    a = (1 - level) / 2
    return (solve(lambda mu: cdf(k - 1, mu) - (1 - a)) if k else 0.0,
            solve(lambda mu: cdf(k, mu) - a))


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    return float("nan") if not n else (xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2)


def kev_catalog(as_of):
    """CISA's own fields for each KEV entry, from the newest cached catalog not after as_of.
    The NVD sweep carries only the date added; ransomware use and CISA's product name are here."""
    snaps = sorted(p for p in DATA.glob("cisa_kev_*.json") if p.stem[9:] <= str(as_of))
    if not snaps:
        return {}, None
    return ({v["cveID"]: v for v in json.loads(snaps[-1].read_text())["vulnerabilities"]},
            snaps[-1].name)


def family_group(fam):
    return next((name for rx, name in FAMILY_GROUPS if rx.search(fam)), fam)


def ptype_tables(rows, pub, kev, start, as_of, per_type=8, min_mix=20):
    """Everything the product-type section and the data page's figures report."""
    N, K = len(pub), len(kev)
    typed = Counter(r["ptype"] for r in pub if r["ptype_source"] == "cpe")
    by_vendor = Counter(r["ptype"] for r in pub if r["ptype_source"] == "vendor")
    # publications with no type: a vendor with at least min_mix CPE-typed CVEs in the window is
    # spread over the types in that proportion, any other named vendor is long-tail software and
    # goes to `other`, and records with no vendor at all follow the mix of everything else
    mix = defaultdict(Counter)
    for r in pub:
        if r["ptype_source"] == "cpe":
            mix[r["vendor"]][r["ptype"]] += 1
    imputed = {t: float(typed[t] + by_vendor[t]) for t in PTYPES}
    spread = to_other = nameless = 0
    rest = []                                # every publication counted as `other`, whole
    for r in pub:
        if r["ptype"]:
            if r["ptype"] == "other":
                rest.append(r)
            continue
        m = mix.get(r["vendor"]) if r["vendor"] else None
        if not r["vendor"]:
            nameless += 1
        elif m and sum(m.values()) >= min_mix:
            spread += 1
            for t, n in m.items():
                imputed[t] += n / sum(m.values())
        else:
            to_other += 1
            imputed["other"] += 1
            rest.append(r)
    base = sum(imputed.values())
    for t in PTYPES:
        imputed[t] += nameless * imputed[t] / base
    kadd = Counter(r["ptype"] or "(untyped)" for r in kev)
    types = {}
    for t in PTYPES:
        lo, hi = poisson_interval(kadd[t])
        types[t] = {
            "name": PTYPE_NAME[t], "published_cpe": typed[t], "published_vendor": by_vendor[t],
            "published_imputed": round(imputed[t], 1), "kev_added": kadd[t],
            "share_published": imputed[t] / N, "share_kev": kadd[t] / K if K else 0.0,
            "per_1000": 1000 * kadd[t] / imputed[t],
            "per_1000_lo": 1000 * lo / imputed[t], "per_1000_hi": 1000 * hi / imputed[t],
            "per_1000_cpe_only": 1000 * kadd[t] / typed[t] if typed[t] else None,
            "lift": (kadd[t] / K) / (imputed[t] / N) if K else None}
    cross = {t: {e: [0, 0] for e in EXPOSURES} for t in PTYPES}
    for rs, i in ((pub, 0), (kev, 1)):
        for r in rs:
            if r["ptype_source"] == "cpe":
                cross[r["ptype"]][r["exposure"]][i] += 1

    # what `other` is made of, along fields NVD records: who assigned the CVE, whether NVD has
    # analyzed it (only then does it have CPE and can it be matched to KEV at all), and for the
    # analyzed ones the CPE part and the platform the product runs on
    kev_other = [r for r in kev if r["ptype"] == "other"]
    cat_other = [r for r in rows if r["ptype"] == "other" and r["kev_added"]
                 and r["kev_added"] <= str(as_of)]

    def split(key, many=False):
        out = defaultdict(lambda: {"published": 0, "with_cpe": 0, "kev_added": 0,
                                   "kev_catalog": 0})
        for rs, field in ((rest, "published"), (kev_other, "kev_added"),
                          (cat_other, "kev_catalog")):
            for r in rs:
                for k in (key(r) if many else [key(r)]):
                    out[k][field] += 1
                    if field == "published" and r["ptype_source"] == "cpe":
                        out[k]["with_cpe"] += 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]["published"]))
    analyzed = lambda r: r["ptype_source"] == "cpe"
    inside = {
        "published": len(rest), "with_cpe": sum(1 for r in rest if analyzed(r)),
        "by_channel": split(lambda r: r["channel"]),
        "by_cpe_part": split(lambda r: (r.get("cpe_part") or "(none recorded)")
                             if analyzed(r) else "(no CPE)"),
        "by_target_sw": split(lambda r: (r["target_sw"].split("|") if r.get("target_sw")
                                         else ["(none: runs on its own)"])
                              if analyzed(r) else ["(no CPE)"], many=True)}

    # the whole catalog, whatever the window: composition by year added, and a profile per type
    catalog, snap = kev_catalog(as_of)
    allkev = [r for r in rows if r["kev_added"] and r["kev_added"] <= str(as_of) and r["ptype"]]
    years = sorted({r["kev_added"][:4] for r in allkev})
    by_year = {y: {t: 0 for t in PTYPES} for y in years}
    for r in allkev:
        by_year[r["kev_added"][:4]][r["ptype"]] += 1
    lag = lambda r: (dt.date.fromisoformat(r["kev_added"])
                     - dt.date.fromisoformat(r["published"])).days
    name = lambda r: "{vendorProject} / {product}".format(**catalog[r["cve"]])
    profile = {}
    for t in PTYPES:
        rs = [r for r in allkev if r["ptype"] == t]
        since = [lag(r) for r in rs if r["published"] >= KEV_OPENED]
        known = [r for r in rs if r["cve"] in catalog]
        frac = lambda xs, f: sum(1 for x in xs if f(x)) / len(xs) if xs else None
        profile[t] = {
            "entries": len(rs),
            "remote_unauthenticated": frac(rs, lambda r: r["exposure"] == EXPOSURES[0]),
            "local": frac(rs, lambda r: r["exposure"] == EXPOSURES[2]),
            "automatable": frac(rs, lambda r: r["ssvc_automatable"] == "yes"),
            "ransomware": frac(known, lambda r: catalog[r["cve"]]
                               ["knownRansomwareCampaignUse"] == "Known"),
            "published_since_kev_opened": len(since), "lag_median_days": median(since),
            "within_7_days": frac(since, lambda d: d <= 7),
            "within_30_days": frac(since, lambda d: d <= 30),
            "after_a_year": frac(since, lambda d: d > 365),
            "products": len({name(r) for r in known}),
            "top5_share": (sum(n for _, n in Counter(name(r) for r in known).most_common(5))
                           / len(known) if known else None)}

    # families: a CVE counts under each family group it lists. Distributions are left out, and
    # so is Siemens, whose appliances list the firewall software they host.
    skip, gtype = REPACKAGERS | {"siemens"}, {}
    fam = defaultdict(lambda: {"published": 0, "kev_added": 0, "kev_catalog": 0, "years": set(),
                               "ransomware": 0, "lags": [], "unauth": 0})
    for r in rows:
        if not r["families"]:
            continue
        groups = set()
        for f in r["families"].split("|"):
            if f.split(":")[0] not in skip:
                groups.add(family_group(f))
                gtype.setdefault(family_group(f), family_ptype(f))
        in_pub = str(start) < r["published"] <= str(as_of)
        in_kev = bool(r["kev_added"]) and str(start) < r["kev_added"] <= str(as_of)
        for g in groups:
            c = fam[g]
            c["published"] += in_pub
            c["kev_added"] += in_kev
            if r["kev_added"] and r["kev_added"] <= str(as_of):
                c["kev_catalog"] += 1
                c["years"].add(r["kev_added"][:4])
                c["unauth"] += r["exposure"] == EXPOSURES[0]
                c["ransomware"] += (catalog.get(r["cve"], {})
                                    .get("knownRansomwareCampaignUse") == "Known")
                if r["published"] >= KEV_OPENED:
                    c["lags"].append(lag(r))
    top = {t: [] for t in PTYPES}
    for g, c in sorted(fam.items(), key=lambda kv: (-kv[1]["kev_added"], -kv[1]["kev_catalog"],
                                                    kv[0])):
        t = gtype[g]
        if c["kev_added"] and len(top[t]) < per_type:
            lo, hi = poisson_interval(c["kev_added"])
            p = c["published"]
            top[t].append({
                "family": g, "published": p, "kev_added": c["kev_added"],
                "per_1000": 1000 * c["kev_added"] / p if p else None,
                "per_1000_lo": 1000 * lo / p if p else None,
                "per_1000_hi": 1000 * hi / p if p else None,
                "share_of_type": c["kev_added"] / kadd[t] if kadd[t] else None,
                "kev_catalog": c["kev_catalog"], "years_with_additions": len(c["years"]),
                "catalog_years": len(years), "ransomware": c["ransomware"],
                "remote_unauthenticated": c["unauth"] / c["kev_catalog"],
                "lag_median_days": median(c["lags"]) if c["lags"] else None})
    return {"as_of": str(as_of), "window_days": (as_of - start).days, "published": N,
            "kev_added": K, "kev_untyped": kadd["(untyped)"], "catalog_snapshot": snap,
            "coverage": {"cpe": sum(typed.values()) / N, "vendor": sum(by_vendor.values()) / N,
                         "spread_by_vendor_mix": spread / N, "long_tail_to_other": to_other / N,
                         "no_vendor": nameless / N},
            "types": types, "type_by_exposure": cross, "inside_other": inside,
            "kev_by_year_added": by_year,
            "kev_profile": profile, "top_families": top}


def ptype_section(P):
    """The product-type tables of the report, as markdown lines."""
    T, cov = P["types"], P["coverage"]
    pct = lambda x: "—" if x is None else f"{x:.0%}"
    num = lambda x, f="{:.1f}": "—" if x is None or x != x else f.format(x)
    L = ["", "## By product type", "",
         "`ptype` sorts each CVE by what the affected product is for: " +
         "; ".join(f"**{T[t]['name']}** (`{t}`)" for t in PTYPES) + ". The rules are "
         "`PTYPE_RULES` in `cve_strata.py`, applied to the CPE families of the CVE's own "
         f"vendor. CPE types {cov['cpe']:.1%} of the window's publications and every KEV "
         f"addition. The rest are typed without it: {cov['vendor']:.1%} by a vendor that ships "
         f"one type, {cov['spread_by_vendor_mix']:.1%} spread over the types in proportion to "
         f"their vendor's typed CVEs, {cov['long_tail_to_other']:.1%} from other named vendors "
         f"counted as *other*, and {cov['no_vendor']:.1%} with no vendor following the overall "
         "mix. That is the *imputed* column; *CPE only* drops all of them and so overstates "
         "every rate, and the truth lies between the two. Intervals are exact Poisson 95% on "
         "the count of additions, with the denominator taken as known.", "",
         "| product type | published, CPE only | published, imputed | share | KEV additions "
         "| share | per 1,000 (imputed) | 95% interval | per 1,000 (CPE only) | lift |",
         "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for t in PTYPES:
        c = T[t]
        L.append(f"| {c['name']} | {c['published_cpe']:,} | {c['published_imputed']:,.0f} | "
                 f"{c['share_published']:.1%} | {c['kev_added']} | {c['share_kev']:.1%} | "
                 f"{c['per_1000']:.1f} | {c['per_1000_lo']:.1f}–{c['per_1000_hi']:.1f} | "
                 f"{num(c['per_1000_cpe_only'])} | {c['lift']:.1f}× |")
    L.append(f"| **all** | {sum(c['published_cpe'] for c in T.values()):,} | {P['published']:,} "
             f"| 100% | {P['kev_added']} | 100% | {1000 * P['kev_added'] / P['published']:.1f} "
             "| | | 1.0× |")
    if P["kev_untyped"]:
        L += ["", f"{P['kev_untyped']} KEV additions have no CPE yet and are in no row."]

    L += ["", "### Product type × exposure: KEV additions / published, per 1,000", "",
          "CPE-typed records only, on both sides, so these rates are upper bounds.", "",
          "| product type | " + " | ".join(EXPOSURES) + " |", "|---|" + "---:|" * len(EXPOSURES)]
    for t in PTYPES:
        cells = []
        for e in EXPOSURES:
            p, k = P["type_by_exposure"][t][e]
            cells.append(f"{k}/{p:,} = {1000 * k / p:.1f}" if p else (f"{k}/0" if k else "—"))
        L.append(f"| {T[t]['name']} | " + " | ".join(cells) + " |")

    I = P["inside_other"]
    PART = {"a": "application", "o": "operating system or firmware", "h": "hardware",
            "a|o": "application and OS/firmware", "h|o": "hardware and its firmware",
            "a|h": "application and hardware", "a|h|o": "all three"}
    head = ["| published | with CPE | KEV additions | KEV, whole catalog |", "---:|---:|---:|---:|"]
    line = lambda name, c: (f"| {name} | {c['published']:,} | {c['with_cpe']:,} | "
                            f"{c['kev_added']} | {c['kev_catalog']} |")
    L += ["", "### Inside *other*", "",
          f"*Other* is a remainder, so it is split here only along fields NVD records. Of its "
          f"{I['published']:,} publications, {I['with_cpe']:,} have CPE. The rest are unanalyzed "
          "(most are marked Deferred), and since every KEV entry has CPE they cannot be matched "
          "to the catalog: their zero is a limit of the measurement, not a rate. Counts here "
          "are whole records, without the proportional shares the table above spreads from "
          "multi-type vendors.", "",
          "**By who assigned the CVE** (`channel`, from NVD's `sourceIdentifier`)", "",
          "| channel " + head[0], "|---|" + head[1]]
    L += [line(k, c) for k, c in I["by_channel"].items()]
    L += ["", "**By CPE part of the vulnerable products** (`cpe_part`)", "",
          "| part " + head[0], "|---|" + head[1]]
    L += [line(PART.get(k, k), c) for k, c in I["by_cpe_part"].items()]
    sw = list(I["by_target_sw"].items())
    L += ["", "**By the platform the product runs on** (`target_sw`): the 12 largest. A value "
          "here marks a plugin, package or extension; none marks a product that stands alone. "
          "A CVE listing several platforms counts under each.", "",
          "| target software " + head[0], "|---|" + head[1]]
    L += [line(f"`{k}`" if not k.startswith("(") else k, c) for k, c in sw[:12]]

    Y = P["kev_by_year_added"]
    L += ["", "### Share of KEV additions by year added, whole catalog", "",
          "No denominators before the table's floor, so this is composition only. It shows "
          "which of the window's shares are habits of the catalog and which are one year's.",
          "", "| year added | entries | " + " | ".join(T[t]["name"] for t in PTYPES) + " |",
          "|---|---:|" + "---:|" * len(PTYPES)]
    for y, c in Y.items():
        n = sum(c.values())
        L.append(f"| {y} | {n} | " + " | ".join(f"{c[t] / n:.0%}" for t in PTYPES) + " |")

    R = P["kev_profile"]
    L += ["", "### What each type's KEV entries look like, whole catalog", "",
          f"Timing rows use entries published since the catalog opened ({KEV_OPENED}); older "
          "ones were added in bulk and their lag measures the catalog, not the attacker. "
          f"Ransomware use and product names are CISA's, from `{P['catalog_snapshot']}`.", "",
          "| | " + " | ".join(T[t]["name"] for t in PTYPES) + " |",
          "|---|" + "---:|" * len(PTYPES)]
    for label, key, f in [
            ("KEV entries", "entries", lambda x: f"{x:,}"),
            ("known ransomware use", "ransomware", pct),
            ("remote, no privileges, no user action", "remote_unauthenticated", pct),
            ("local or physical", "local", pct),
            ("automatable (SSVC)", "automatable", pct),
            ("published since the catalog opened", "published_since_kev_opened",
             lambda x: f"{x:,}"),
            ("median days, publication to KEV", "lag_median_days", lambda x: num(x, "{:g}")),
            ("in KEV within 7 days", "within_7_days", pct),
            ("in KEV within 30 days", "within_30_days", pct),
            ("in KEV after more than a year", "after_a_year", pct),
            ("distinct products (CISA's names)", "products", lambda x: f"{x:,}"),
            ("share held by the five most-listed products", "top5_share", pct)]:
        L.append(f"| {label} | " + " | ".join(f(R[t][key]) for t in PTYPES) + " |")

    L += ["", "### Families with the most KEV additions, per type", "",
          "Ranked by KEV additions in the window, then by entries in the whole catalog. A CVE "
          "counts under every family it lists, and a trailing `*` marks releases grouped into "
          "one family (`FAMILY_GROUPS`). Published counts need CPE, so a family whose recent "
          "CVEs are unanalyzed shows a rate that is too high; with fewer than about 30 "
          "published the interval says how little the rate means. *Years* is how many of the "
          "catalog's years the family was added in.", ""]
    for t in PTYPES:
        L += [f"**{T[t]['name']}**", "",
              "| family | published | KEV additions | per 1,000 | 95% interval | share of type "
              "| in catalog | years | ransomware | remote unauth. | median lag, days |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for f in P["top_families"][t]:
            iv = (f"{f['per_1000_lo']:.0f}–{f['per_1000_hi']:.0f}" if f["published"] else "—")
            L.append(f"| `{f['family']}` | {f['published']:,} | {f['kev_added']} | "
                     f"{num(f['per_1000'], '{:.0f}')} | {iv} | {pct(f['share_of_type'])} | "
                     f"{f['kev_catalog']} | {f['years_with_additions']}/{f['catalog_years']} | "
                     f"{f['ransomware']} | {pct(f['remote_unauthenticated'])} | "
                     f"{num(f['lag_median_days'], '{:g}')} |")
        L.append("")
    return L[:-1]


def misallocation(cells):
    """Share of KEV additions a single population-wide rate puts in the wrong cell:
    half the summed |observed - expected|, over the total. 0 means composition is explained
    by volume alone; this is the quantity a stratified model exists to reduce."""
    n = sum(p for p, _ in cells.values())
    k = sum(x for _, x in cells.values())
    if not n or not k:
        return float("nan")
    return 0.5 * sum(abs(x - k * p / n) for p, x in cells.values()) / k


def report(args):
    meta = json.loads(META.read_text())
    rows = [set_ptype(r) for r in read_table().values()]
    # reconcile assigner spellings to CPE vendors that differ only by separators
    # ('palo_alto_networks' -> 'paloaltonetworks'); anything else is left as the assigner wrote it
    squash = lambda v: v.replace("_", "").replace("-", "")
    cpe_names = {squash(r["vendor"]): r["vendor"] for r in rows if r["vendor_source"] == "cpe"}
    for r in rows:
        if r["vendor_source"] == "assigner":
            r["vendor"] = cpe_names.get(squash(r["vendor"]), r["vendor"])
    as_of = dt.date.fromisoformat(args.as_of or meta["last_sync"][:10])
    start = as_of - dt.timedelta(days=args.window_days)
    if str(start) < meta["floor"]:
        print(f"note: window starts {start}, before the table's floor {meta['floor']}")
    in_win = lambda d: bool(d) and str(start) < d <= str(as_of)
    pub = [r for r in rows if in_win(r["published"])]
    kev = [r for r in rows if in_win(r["kev_added"])]
    cohort = [r for r in pub if r["kev_added"]]
    N, K = len(pub), len(kev)

    top = [v for v, _ in Counter(r["vendor"] for r in kev if r["vendor"]).most_common(args.top)]
    vclass = lambda r: (r["vendor"] if r["vendor"] in top
                        else "(other vendors)" if r["vendor"] else "(no vendor recorded)")
    vendors = top + ["(other vendors)", "(no vendor recorded)"]

    def tally(key):
        cells = defaultdict(lambda: [0, 0, 0])
        for r in pub:
            cells[key(r)][0] += 1
        for r in kev:
            cells[key(r)][1] += 1
        for r in cohort:
            cells[key(r)][2] += 1
        return cells

    def table(cells, order, head):
        out = [f"| {head} | published | share | KEV additions | share | per 1,000 published "
               "| lift | published in window and in KEV |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for name in order:
            p, k, c = cells.get(name, (0, 0, 0))
            rate = 1000 * k / p if p else float("nan")
            lift = (k / K) / (p / N) if p and K else float("nan")
            out.append(f"| {name} | {p:,} | {p / N:.1%} | {k} | {k / K:.1%} | {rate:.1f} | "
                       f"{lift:.1f}× | {c} |")
        out.append(f"| **all** | {N:,} | 100% | {K} | 100% | {1000 * K / N:.1f} | 1.0× "
                   f"| {len(cohort)} |")
        return out

    share = lambda rs, f: sum(1 for r in rs if f(r)) / len(rs) if rs else float("nan")
    L = [f"# CVE stratification — {args.window_days} days to {as_of}", "",
         f"Built by `cve_strata.py report` from `data/cve_strata.csv.gz` (last synced with NVD "
         f"{meta['last_sync']} UTC, table floor {meta['floor']}). **Published**: {N:,} CVEs "
         f"with an NVD publication date in ({start}, {as_of}]. **KEV additions**: {K} CVEs "
         f"CISA added in the same window, whatever their publication date; {len(cohort)} of "
         f"them were also published in it. *Per 1,000 published* divides the two, the "
         f"stratified analogue of the model's conversion; *lift* is a class's share of KEV "
         f"additions over its share of publications.", "",
         "## Coverage of each field", "",
         "| field | published in window | KEV additions |", "|---|---:|---:|"]
    for name, f in [("vendor from NVD CPE applicability", lambda r: r["vendor_source"] == "cpe"),
                    ("vendor from the assigner's `affected` block",
                     lambda r: r["vendor_source"] == "assigner"),
                    ("any vendor", lambda r: bool(r["vendor"])),
                    ("CVSS vector (exposure class)", lambda r: bool(r["av"])),
                    ("… scored by NVD itself", lambda r: r["cvss_type"] == "Primary"),
                    ("weakness type (CWE)", lambda r: bool(r["cwes"])),
                    ("SSVC decision points (CISA)", lambda r: bool(r["ssvc_exploitation"]))]:
        L.append(f"| {name} | {share(pub, f):.1%} | {share(kev, f):.1%} |")

    ex, ve = tally(lambda r: r["exposure"]), tally(vclass)
    both = tally(lambda r: (vclass(r), r["exposure"]))
    L += ["", "## By exposure class", ""] + table(ex, EXPOSURES, "exposure (CVSS)")
    L += ["", f"## By vendor: the {len(top)} with most KEV additions, and the rest", "",
          "Vendors are chosen by exploitation, not volume. Rates for vendors whose CVEs are "
          "often unanalyzed are overstated to the extent their publications sit in "
          "*(no vendor recorded)*.", ""] + table(ve, vendors, "vendor")

    L += ["", "## Vendor × exposure: KEV additions / published, per 1,000", "",
          "| vendor | " + " | ".join(EXPOSURES) + " |", "|---|" + "---:|" * len(EXPOSURES)]
    for v in vendors:
        cells = []
        for e in EXPOSURES:
            p, k, _ = both.get((v, e), (0, 0, 0))
            cells.append(f"{k}/{p:,} = {1000 * k / p:.1f}" if p else (f"{k}/0" if k else "—"))
        L.append(f"| {v} | " + " | ".join(cells) + " |")

    by_cwe = defaultdict(lambda: [0, 0, 0])
    for rs, i in ((pub, 0), (kev, 1), (cohort, 2)):
        for r in rs:
            for c in (r["cwes"].split("|") if r["cwes"] else ["(none)"]):
                by_cwe[c][i] += 1
    cw_top = [c for c, _ in sorted(by_cwe.items(), key=lambda t: -t[1][1])[:15]]
    L += ["", "## By weakness type: the 15 with most KEV additions", "",
          "A CVE with several CWEs counts under each, so these rows overlap and do not sum.", ""]
    L += table(by_cwe, cw_top, "CWE")[:-1]

    sev = tally(lambda r: r["severity"] or "unscored")
    L += ["", "## By CVSS severity", ""] + table(
        sev, [s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "unscored") if s in sev],
        "severity")
    sv = tally(lambda r: r["ssvc_exploitation"] or "(not assessed)")
    L += ["", "## By CISA's SSVC exploitation value", "",
          "CISA's own assessment at the time it enriched the record: `none`, `poc` (a public "
          "proof of concept) or `active`. KEV additions are `active` by construction; the "
          "useful rows are how many published CVEs carry `poc`, the supply a PoC-conditioned "
          "hazard would act on.", ""] + table(
        sv, [s for s in ("active", "poc", "none", "(not assessed)") if s in sv], "exploitation")
    auto = tally(lambda r: r["ssvc_automatable"] or "(not assessed)")
    L += ["", "## By SSVC automatable", ""] + table(
        auto, [s for s in ("yes", "no", "(not assessed)") if s in auto], "automatable")

    P = ptype_tables(rows, pub, kev, start, as_of)
    L += ptype_section(P)
    pt = {t: (c["published_imputed"], c["kev_added"]) for t, c in P["types"].items()}

    pk = lambda cells: {n: (c[0], c[1]) for n, c in cells.items()}
    L += ["", "## How much composition a single population rate misses", "",
          "Share of KEV additions that one population-wide rate assigns to the wrong class "
          "(half the summed absolute difference between observed and expected additions). "
          "This is the baseline a stratified calibration has to beat without being fitted "
          "to it.", "", "| partition | classes | misallocated |", "|---|---:|---:|",
          f"| exposure | {len(ex)} | {misallocation(pk(ex)):.1%} |",
          f"| vendor (top {len(top)} + 2) | {len(ve)} | {misallocation(pk(ve)):.1%} |",
          f"| vendor × exposure | {len(both)} | {misallocation(pk(both)):.1%} |",
          f"| severity | {len(sev)} | {misallocation(pk(sev)):.1%} |",
          f"| product type (imputed publications) | {len(pt)} | {misallocation(pt):.1%} |", ""]

    md = ROOT / f"cve_stratification_{as_of}.md"
    md.write_text("\n".join(L))
    out = DATA / f"cve_stratification_{as_of}.csv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["vendor", "exposure", "published", "kev_added_in_window",
                    "published_in_window_and_in_kev"])
        for v in vendors:
            for e in EXPOSURES:
                w.writerow([v, e, *both.get((v, e), (0, 0, 0))])
    pj = DATA / f"cve_ptype_{as_of}.json"
    pj.write_text(json.dumps(P, indent=1))
    print("\n".join(L))
    print(f"\nwrote {md.name}, {out.relative_to(ROOT)} and {pj.relative_to(ROOT)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="full sweep by publication date")
    b.add_argument("--start", required=True)
    b.add_argument("--end", required=True)
    b.add_argument("--fresh", action="store_true", help="discard the existing table first")
    sub.add_parser("update", help="refresh rows NVD modified since the last sync")
    sub.add_parser("retype", help="reapply the product-type rules to the table; no network")
    r = sub.add_parser("report", help="write the stratification tables; no network")
    r.add_argument("--as-of")
    r.add_argument("--window-days", type=int, default=365)
    r.add_argument("--top", type=int, default=20)
    args = ap.parse_args()
    {"build": build, "update": update, "retype": retype, "report": report}[args.cmd](args)
