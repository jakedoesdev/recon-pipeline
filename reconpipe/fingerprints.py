"""Subdomain takeover and infrastructure exposure fingerprints."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TakeoverFingerprint:
    service: str
    cname_patterns: list[str]
    body_patterns: list[str]
    nxdomain_vulnerable: bool = False
    negative_body_patterns: list[str] | None = None
    negative_status_codes: list[int] | None = None


BUILTIN_FINGERPRINTS: list[TakeoverFingerprint] = [
    TakeoverFingerprint(
        service="s3",
        cname_patterns=[".s3.amazonaws.com", ".s3-website"],
        body_patterns=["NoSuchBucket", "The specified bucket does not exist"],
    ),
    TakeoverFingerprint(
        service="azure_blob",
        cname_patterns=[".blob.core.windows.net"],
        body_patterns=["BlobNotFound", "The specified container does not exist"],
    ),
    TakeoverFingerprint(
        service="azure_webapp",
        cname_patterns=[".azurewebsites.net"],
        body_patterns=["404 Web Site not found", "Microsoft Azure App Service"],
    ),
    TakeoverFingerprint(
        service="github_pages",
        cname_patterns=[".github.io"],
        body_patterns=["There isn't a GitHub Pages site here", "For root URLs"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="heroku",
        cname_patterns=[".herokuapp.com", ".herokudns.com", ".herokussl.com"],
        body_patterns=["No such app", "no-such-app"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="shopify",
        cname_patterns=[".myshopify.com"],
        body_patterns=["Sorry, this shop is currently unavailable", "Only one step left"],
    ),
    TakeoverFingerprint(
        service="fastly",
        cname_patterns=[".fastly.net", ".fastlylb.net"],
        body_patterns=["Fastly error: unknown domain"],
    ),
    TakeoverFingerprint(
        service="pantheon",
        cname_patterns=[".pantheonsite.io"],
        body_patterns=["404 error unknown site", "The gods are wise"],
    ),
    TakeoverFingerprint(
        service="tumblr",
        cname_patterns=[".tumblr.com"],
        body_patterns=["There's nothing here", "Whatever you were looking for doesn't currently exist"],
    ),
    TakeoverFingerprint(
        service="unbounce",
        cname_patterns=[".unbouncepages.com"],
        body_patterns=["The requested URL was not found on this server"],
    ),
    TakeoverFingerprint(
        service="wordpress",
        cname_patterns=[".wordpress.com"],
        body_patterns=["Do you want to register"],
    ),
    TakeoverFingerprint(
        service="surge",
        cname_patterns=[".surge.sh"],
        body_patterns=["project not found"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="bitbucket",
        cname_patterns=[".bitbucket.io"],
        body_patterns=["Repository not found"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="ghost",
        cname_patterns=[".ghost.io"],
        body_patterns=["The thing you were looking for is no longer here"],
    ),
    TakeoverFingerprint(
        service="netlify",
        cname_patterns=[".netlify.app", ".netlify.com"],
        body_patterns=["Not Found - Request ID"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="fly_io",
        cname_patterns=[".fly.dev"],
        body_patterns=["404 Not Found"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="cloudfront",
        cname_patterns=[".cloudfront.net"],
        body_patterns=["Bad request", "ERROR: The request could not be satisfied"],
        negative_body_patterns=["Request blocked"],
        negative_status_codes=[403],
    ),
]


# ---------------------------------------------------------------------------
# Infrastructure / OT / ICS login page fingerprints
# ---------------------------------------------------------------------------

@dataclass
class InfraFingerprint:
    category: str       # "network", "ics", "mgmt", "iot"
    device: str         # short identifier, e.g. "fortinet", "siemens"
    title_patterns: list[str] = field(default_factory=list)
    body_patterns: list[str] = field(default_factory=list)
    server_patterns: list[str] = field(default_factory=list)


INFRA_FINGERPRINTS: list[InfraFingerprint] = [
    # ── Network infrastructure ─────────────────────────────────────────
    InfraFingerprint(
        category="network", device="fortinet",
        title_patterns=["FortiGate", "FortiOS", "Fortinet"],
        body_patterns=["FortiGate", "FortiOS", "fortinet"],
    ),
    InfraFingerprint(
        category="network", device="paloalto",
        title_patterns=["Palo Alto Networks", "GlobalProtect Portal"],
        body_patterns=["Palo Alto Networks", "GlobalProtect"],
    ),
    InfraFingerprint(
        category="network", device="sonicwall",
        title_patterns=["SonicWall", "SonicWALL"],
        body_patterns=["SonicWall", "SonicWALL"],
        server_patterns=["SonicWALL"],
    ),
    InfraFingerprint(
        category="network", device="cisco",
        title_patterns=["Cisco", "ASDM", "Adaptive Security Appliance",
                        "Cisco Meraki", "Cisco Webex"],
        body_patterns=["Cisco Systems", "Adaptive Security Appliance"],
        server_patterns=["cisco-IOS"],
    ),
    InfraFingerprint(
        category="network", device="juniper",
        title_patterns=["Juniper", "Junos", "J-Web"],
        body_patterns=["Juniper Networks", "J-Web"],
    ),
    InfraFingerprint(
        category="network", device="pfsense",
        title_patterns=["pfSense", "pfsense"],
        body_patterns=["pfSense", "pfsense"],
    ),
    InfraFingerprint(
        category="network", device="opnsense",
        title_patterns=["OPNsense"],
        body_patterns=["OPNsense"],
    ),
    InfraFingerprint(
        category="network", device="mikrotik",
        title_patterns=["MikroTik", "RouterOS", "Mikrotik"],
        body_patterns=["MikroTik", "RouterOS", "mikrotik"],
    ),
    InfraFingerprint(
        category="network", device="ubiquiti",
        title_patterns=["UniFi", "Ubiquiti", "airOS", "EdgeOS", "UNMS"],
        body_patterns=["Ubiquiti", "UniFi", "airOS"],
    ),
    InfraFingerprint(
        category="network", device="aruba",
        title_patterns=["Aruba", "ArubaOS"],
        body_patterns=["Aruba Networks", "ArubaOS"],
    ),
    InfraFingerprint(
        category="network", device="netgear",
        title_patterns=["NETGEAR"],
        body_patterns=["NETGEAR"],
    ),
    InfraFingerprint(
        category="network", device="f5",
        title_patterns=["BIG-IP", "F5 Networks"],
        body_patterns=["BIG-IP", "F5 Networks"],
        server_patterns=["BigIP", "BIG-IP"],
    ),
    InfraFingerprint(
        category="network", device="checkpoint",
        title_patterns=["Check Point", "Gaia Portal"],
        body_patterns=["Check Point Software", "Gaia Portal"],
    ),
    InfraFingerprint(
        category="network", device="watchguard",
        title_patterns=["WatchGuard", "Fireware"],
        body_patterns=["WatchGuard Technologies"],
    ),
    InfraFingerprint(
        category="network", device="zyxel",
        title_patterns=["ZyXEL", "Zyxel", "ZyWALL"],
        body_patterns=["ZyXEL", "Zyxel"],
    ),

    # ── OT / ICS / SCADA ──────────────────────────────────────────────
    InfraFingerprint(
        category="ics", device="siemens",
        title_patterns=["SIMATIC", "Siemens", "WinCC", "S7-"],
        body_patterns=["SIMATIC", "Siemens AG", "WinCC"],
    ),
    InfraFingerprint(
        category="ics", device="schneider",
        title_patterns=["Schneider Electric", "Modicon", "PowerLogic",
                        "EcoStruxure"],
        body_patterns=["Schneider Electric", "Modicon", "EcoStruxure"],
    ),
    InfraFingerprint(
        category="ics", device="rockwell",
        title_patterns=["Allen-Bradley", "Rockwell", "FactoryTalk",
                        "CompactLogix", "ControlLogix"],
        body_patterns=["Allen-Bradley", "Rockwell Automation", "FactoryTalk"],
    ),
    InfraFingerprint(
        category="ics", device="ge",
        title_patterns=["GE Intelligent Platforms", "Proficy", "CIMPLICITY",
                        "iFIX"],
        body_patterns=["GE Intelligent Platforms", "Proficy", "CIMPLICITY"],
    ),
    InfraFingerprint(
        category="ics", device="honeywell",
        title_patterns=["Honeywell", "Experion", "Tridium", "Niagara"],
        body_patterns=["Honeywell", "Experion", "Tridium", "Niagara Framework"],
        server_patterns=["Niagara"],
    ),
    InfraFingerprint(
        category="ics", device="ignition",
        title_patterns=["Ignition Gateway", "Ignition by Inductive Automation"],
        body_patterns=["Inductive Automation", "Ignition Gateway"],
    ),
    InfraFingerprint(
        category="ics", device="wonderware",
        title_patterns=["Wonderware", "InTouch", "AVEVA"],
        body_patterns=["Wonderware", "AVEVA"],
    ),
    InfraFingerprint(
        category="ics", device="emerson",
        title_patterns=["Emerson", "DeltaV", "Ovation"],
        body_patterns=["Emerson Electric", "DeltaV"],
    ),
    InfraFingerprint(
        category="ics", device="moxa",
        title_patterns=["Moxa", "EDS-", "NPort"],
        body_patterns=["Moxa Inc", "Moxa"],
        server_patterns=["Moxa"],
    ),
    InfraFingerprint(
        category="ics", device="advantech",
        title_patterns=["Advantech", "WebAccess", "ADAM-"],
        body_patterns=["Advantech", "WebAccess"],
    ),

    # ── Out-of-band / server management ────────────────────────────────
    InfraFingerprint(
        category="mgmt", device="ilo",
        title_patterns=["iLO", "Integrated Lights-Out"],
        body_patterns=["Integrated Lights-Out", "iLO"],
    ),
    InfraFingerprint(
        category="mgmt", device="idrac",
        title_patterns=["iDRAC", "Dell Remote Access"],
        body_patterns=["iDRAC", "Dell Remote Access Controller"],
    ),
    InfraFingerprint(
        category="mgmt", device="ipmi",
        title_patterns=["IPMI", "Supermicro"],
        body_patterns=["IPMI", "Supermicro"],
    ),
    InfraFingerprint(
        category="mgmt", device="esxi",
        title_patterns=["VMware ESXi"],
        body_patterns=["VMware ESXi"],
    ),
    InfraFingerprint(
        category="mgmt", device="vcenter",
        title_patterns=["vSphere", "vCenter"],
        body_patterns=["VMware vSphere", "VMware vCenter"],
    ),
    InfraFingerprint(
        category="mgmt", device="proxmox",
        title_patterns=["Proxmox"],
        body_patterns=["Proxmox VE", "Proxmox Virtual Environment"],
    ),

    # ── IoT / cameras / NAS / building automation ──────────────────────
    InfraFingerprint(
        category="iot", device="hikvision",
        title_patterns=["Hikvision", "HIKVISION"],
        body_patterns=["Hikvision Digital", "HIKVISION"],
    ),
    InfraFingerprint(
        category="iot", device="dahua",
        title_patterns=["Dahua", "DAHUA"],
        body_patterns=["Dahua Technology"],
    ),
    InfraFingerprint(
        category="iot", device="axis",
        title_patterns=["AXIS", "Axis Communications"],
        body_patterns=["AXIS Communications", "Axis Communications"],
    ),
    InfraFingerprint(
        category="iot", device="synology",
        title_patterns=["Synology"],
        body_patterns=["Synology"],
    ),
    InfraFingerprint(
        category="iot", device="qnap",
        title_patterns=["QNAP", "QTS"],
        body_patterns=["QNAP Systems"],
    ),
    InfraFingerprint(
        category="iot", device="bacnet",
        title_patterns=["BACnet", "Building Automation"],
        body_patterns=["BACnet"],
    ),
    InfraFingerprint(
        category="iot", device="webcam",
        title_patterns=["IP Camera", "Network Camera", "Web Camera",
                        "NetCam", "IPCam"],
        body_patterns=["IP Camera", "Network Camera"],
        server_patterns=["GoAhead-Webs", "Boa HTTPd", "thttpd"],
    ),
]
