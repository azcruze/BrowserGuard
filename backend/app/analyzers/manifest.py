import json
import re
from urllib.parse import urlparse


class ManifestError(ValueError):
    pass


PERMISSION_CATALOG = {
    "activeTab": ("low", "Temporary access to the active tab after a user gesture.", "Limits access to a user-initiated tab action.", "Prefer activeTab over persistent tab access when feasible.", 2),
    "alarms": ("low", "Schedules deferred extension tasks.", "Background work may continue at scheduled intervals.", "Review alarm frequency and task purpose.", 1),
    "bookmarks": ("high", "Reads and modifies the user's bookmark collection.", "Bookmarks can reveal interests, work, and personal activity.", "Confirm bookmark access is central to the feature.", 12),
    "clipboardRead": ("high", "Reads clipboard content.", "Clipboard data can contain private text, tokens, or copied content.", "Avoid unless directly required and user initiated.", 14),
    "clipboardWrite": ("medium", "Writes content to the clipboard.", "Can replace data the user intended to paste.", "Make clipboard writes explicit and user initiated.", 5),
    "cookies": ("high", "Reads or modifies cookies for permitted sites.", "Cookies can expose session and tracking identifiers.", "Restrict host access and avoid reading authentication cookies.", 16),
    "downloads": ("medium", "Observes and manages browser downloads.", "Download metadata may reveal user activity or files.", "Request only the download actions needed.", 7),
    "geolocation": ("high", "May obtain location when the extension accesses the Geolocation API.", "Location data is sensitive and can identify routines.", "Require clear disclosure and user consent.", 14),
    "history": ("high", "Reads browsing history.", "Visited URLs can reveal sensitive interests and activity.", "Justify the feature and minimize retention.", 16),
    "identity": ("high", "Requests access to sign-in identity information.", "Identity metadata can connect browser activity to a person.", "Request only when authentication is a core feature and explain data handling.", 12),
    "nativeMessaging": ("high", "Communicates with an installed native application.", "Native messaging crosses the browser isolation boundary.", "Document the native host and validate its message protocol.", 15),
    "privacy": ("high", "Reads or changes browser privacy settings.", "Privacy settings can affect the user's browser protections.", "Limit changes to explicit, user-visible configuration.", 13),
    "proxy": ("high", "Changes or observes browser proxy configuration.", "Proxy control can redirect or inspect network traffic.", "Use only for a clearly disclosed network-management feature.", 15),
    "declarativeNetRequest": ("medium", "Applies declared network request rules.", "Rules can block or redirect matching requests.", "Review rule scope and keep rules narrowly targeted.", 6),
    "topSites": ("high", "Reads frequently visited sites.", "Frequently visited sites reveal browsing interests.", "Justify collection and avoid retaining site history.", 11),
    "sessions": ("medium", "Accesses recently closed tabs and windows.", "Session metadata may expose recently viewed pages.", "Limit access to an explicit restore-session action.", 8),
    "search": ("medium", "Uses the browser's search provider.", "Search queries may contain sensitive interests.", "Make query handling transparent and user initiated.", 5),
    "fontSettings": ("low", "Reads or changes browser font settings.", "Settings can reveal preferences and affect page rendering.", "Avoid unrelated settings changes.", 2),
    "webstore": ("low", "Interacts with Chrome Web Store metadata.", "Store information may reveal extension-management activity.", "Limit requests to the extension's stated management feature.", 2),
    "unlimitedStorage": ("medium", "Requests increased extension storage capacity.", "Persistent data can accumulate beyond ordinary storage limits.", "Set retention and size limits for stored data.", 5),
    "declarativeContent": ("low", "Runs actions when declared page conditions match.", "Page conditions may reveal browsing patterns.", "Keep page matching narrow and document triggers.", 2),
    "sidePanel": ("low", "Uses a browser side panel.", "Side panel availability can be associated with browsing sessions.", "Keep displayed data limited to the requested feature.", 1),
    "offscreen": ("medium", "Creates offscreen documents for background work.", "Background documents may process user data outside a visible page.", "Use the narrowest justified reason and close documents promptly.", 5),
    "debugger": ("high", "Uses the Chrome debugger protocol.", "Debugger access can inspect or control substantial browser behavior.", "Treat as highly privileged and justify every debugger command.", 18),
    "contentSettings": ("high", "Reads or changes per-site content settings.", "Site settings changes can weaken browser protections.", "Make changes explicit, reversible, and limited to named sites.", 12),
    "tabGroups": ("low", "Reads and changes tab group metadata.", "Tab group names can contain user-created context.", "Request only for tab organization features.", 2),
    "management": ("high", "Reads information about installed extensions and may manage them.", "Installed-app inventory exposes a user's software environment.", "Use only for an extension-management feature.", 13),
    "notifications": ("low", "Displays desktop notifications.", "Notifications may disclose information on a shared screen.", "Avoid sensitive content in notification text.", 2),
    "scripting": ("high", "Executes scripts in pages when combined with appropriate host access.", "Page content and behavior may be observed or changed.", "Limit script injection to necessary sites and user actions.", 14),
    "storage": ("low", "Stores extension data locally or through Chrome storage APIs.", "Stored data may persist longer than expected.", "Store the minimum data and document retention.", 2),
    "tabs": ("medium", "Reads tab metadata and interacts with tabs.", "Tab URLs and titles may disclose browsing activity.", "Use activeTab or request only needed tab properties.", 8),
    "webNavigation": ("medium", "Observes browser navigation events.", "Navigation patterns may reveal user activity.", "Filter events to the minimum needed.", 8),
    "webRequest": ("high", "Observes network requests on matching hosts.", "Request metadata can expose site and activity information.", "Restrict hosts and review collected request data.", 14),
    "webRequestBlocking": ("high", "May block or modify requests in supported extension contexts.", "Request control can alter browsing behavior and network access.", "Review necessity and limit the set of affected hosts.", 15),
}

COMBINATION_RULES = [
    {"id": "tabs-history", "permissions": {"tabs", "history"}, "title": "Tab metadata with browsing history", "explanation": "Tab access combined with history can provide a broader picture of browsing activity than either permission alone.", "impact": "Tab URLs or titles may be correlated with recorded history.", "mitigation": "Use the narrowest tab fields and avoid retaining history data.", "weight": 9},
    {"id": "tabs-scripting", "permissions": {"tabs", "scripting"}, "title": "Tab access with script injection", "explanation": "This combination can identify tabs and run code in matching pages when host access permits.", "impact": "Page content or behavior may be accessible on eligible sites.", "mitigation": "Limit injection to explicit user actions and narrowly scoped hosts.", "weight": 9},
    {"id": "scripting-broad-host", "permissions": {"scripting"}, "broad_host": True, "title": "Script injection with broad host access", "explanation": "Script injection paired with broad host access has a wide potential page scope.", "impact": "Content and page behavior across matching sites could be accessed.", "mitigation": "Replace broad host patterns with specific origins and use optional permissions.", "weight": 12},
    {"id": "cookies-broad-host", "permissions": {"cookies"}, "broad_host": True, "title": "Cookie access with broad host access", "explanation": "Cookie access for many sites increases the scope of sensitive session-related data available.", "impact": "Cookie identifiers across matching domains could be exposed.", "mitigation": "Limit cookie access to the specific sites required by the feature.", "weight": 12},
    {"id": "history-broad-host", "permissions": {"history"}, "broad_host": True, "title": "History access with broad host access", "explanation": "Browsing history combined with broad site access creates a wide potential observation scope.", "impact": "Browsing activity may be correlated with content from matching sites.", "mitigation": "Narrow host permissions and minimize access to history.", "weight": 10},
]

_SUPPLEMENTAL_PERMISSION_PAIRS = (
    ("activeTab", "tabs"), ("history", "storage"), ("cookies", "storage"),
    ("activeTab", "storage"), ("activeTab", "history"), ("cookies", "tabs"),
    ("cookies", "history"), ("scripting", "storage"),
    ("history", "scripting"), ("history", "webRequest"), ("history", "bookmarks"),
    ("history", "topSites"), ("cookies", "scripting"), ("cookies", "webRequest"),
    ("cookies", "webRequestBlocking"), ("cookies", "identity"), ("scripting", "webRequest"),
    ("scripting", "clipboardRead"), ("scripting", "debugger"), ("webRequest", "webRequestBlocking"),
    ("webRequest", "proxy"), ("tabs", "cookies"), ("tabs", "webRequest"),
    ("tabs", "bookmarks"), ("tabs", "downloads"), ("tabs", "sessions"),
    ("bookmarks", "downloads"), ("bookmarks", "scripting"), ("geolocation", "history"),
    ("geolocation", "tabs"), ("clipboardRead", "history"), ("clipboardRead", "scripting"),
    ("management", "debugger"), ("privacy", "proxy"), ("debugger", "scripting"),
    ("identity", "history"), ("nativeMessaging", "scripting"), ("offscreen", "cookies"),
    ("contentSettings", "proxy"), ("unlimitedStorage", "history"),
)
_EXISTING_PERMISSION_PAIRS = {frozenset(rule["permissions"]) for rule in COMBINATION_RULES if not rule.get("broad_host")}
for _left, _right in _SUPPLEMENTAL_PERMISSION_PAIRS:
    _pair = frozenset((_left, _right))
    if _pair in _EXISTING_PERMISSION_PAIRS:
        continue
    _pair_names = sorted(_pair)
    COMBINATION_RULES.append({
        "id": f"pair-{_pair_names[0]}-{_pair_names[1]}",
        "permissions": _pair,
        "title": f"Combined access: {_pair_names[0]} and {_pair_names[1]}",
        "explanation": "These declarations expose related sensitive browser capabilities; their joint necessity should be reviewed in the context of the extension's stated purpose.",
        "impact": "The combined capabilities could increase the breadth of data or browser actions accessible to the extension.",
        "mitigation": "Validate the need for both capabilities, minimize retained data, and prefer user-initiated access where possible.",
        "weight": 1,
    })

PURPOSE_KEYWORDS = {
    "tabs": {"tab", "window", "browser", "session", "tab manager"},
    "history": {"history", "visited", "browsing history", "recently viewed"},
    "cookies": {"cookie", "session", "sign in", "authentication"},
    "scripting": {"script", "page", "content", "site", "webpage", "automation"},
    "webRequest": {"request", "network", "block", "traffic", "privacy"},
    "webRequestBlocking": {"block", "request", "network", "traffic"},
    "bookmarks": {"bookmark", "favorite", "save links"},
    "downloads": {"download", "file manager"},
    "clipboardRead": {"clipboard", "paste"},
    "clipboardWrite": {"clipboard", "copy"},
    "management": {"extension manager", "manage extensions", "installed extension"},
    "geolocation": {"location", "nearby", "map"},
    "notifications": {"notification", "reminder", "alert"},
    "storage": {"save", "store", "settings", "preference", "sync"},
}

BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def _validate_string_list(value, field):
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ManifestError(f"'{field}' must be an array of non-empty strings.")
    if len(value) > 500:
        raise ManifestError(f"'{field}' contains too many entries.")
    return list(dict.fromkeys(item.strip() for item in value))


def parse_manifest(raw_bytes):
    def reject_constant(value):
        raise ManifestError(f"Invalid JSON numeric constant '{value}'.")

    try:
        manifest = json.loads(raw_bytes.decode("utf-8-sig"), parse_constant=reject_constant)
    except ManifestError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ManifestError("The uploaded manifest is not valid UTF-8 JSON or exceeds safe parser limits.") from error
    if not isinstance(manifest, dict):
        raise ManifestError("A manifest must be a JSON object.")
    name = manifest.get("name")
    version = manifest.get("version")
    manifest_version = manifest.get("manifest_version")
    if not isinstance(name, str) or not name.strip() or len(name) > 200:
        raise ManifestError("Manifest field 'name' must be a non-empty string of at most 200 characters.")
    if not isinstance(version, str) or not re.fullmatch(r"\d+(?:\.\d+){0,3}", version):
        raise ManifestError("Manifest field 'version' must be a dotted numeric version.")
    if not isinstance(manifest_version, int) or isinstance(manifest_version, bool) or manifest_version not in (2, 3):
        raise ManifestError("Manifest field 'manifest_version' must be 2 or 3.")
    description = manifest.get("description", "")
    if not isinstance(description, str) or len(description) > 10000:
        raise ManifestError("Manifest field 'description' must be a string of at most 10,000 characters.")
    permissions = _validate_string_list(manifest.get("permissions", []), "permissions")
    optional_permissions = _validate_string_list(manifest.get("optional_permissions", []), "optional_permissions")
    declared_hosts = manifest.get("host_permissions", [])
    if not declared_hosts and manifest_version == 2:
        legacy_permissions = manifest.get("permissions", [])
        if isinstance(legacy_permissions, list):
            declared_hosts = [
                value for value in legacy_permissions
                if isinstance(value, str) and value.startswith(("http://", "https://", "*://", "<all_urls>"))
            ]
            permissions = [
                value for value in permissions
                if not value.startswith(("http://", "https://", "*://", "<all_urls>"))
            ]
            manifest["permissions"] = [
                value for value in legacy_permissions
                if not (isinstance(value, str) and value.startswith(("http://", "https://", "*://", "<all_urls>")))
            ]
    host_permissions = _validate_string_list(declared_hosts, "host_permissions")
    optional_host_permissions = _validate_string_list(manifest.get("optional_host_permissions", []), "optional_host_permissions")
    content_scripts = manifest.get("content_scripts", [])
    if not isinstance(content_scripts, list) or len(content_scripts) > 100:
        raise ManifestError("'content_scripts' must be an array with at most 100 entries.")
    content_matches = []
    for index, script in enumerate(content_scripts):
        if not isinstance(script, dict):
            raise ManifestError(f"content_scripts[{index}] must be an object.")
        matches = _validate_string_list(script.get("matches", []), f"content_scripts[{index}].matches")
        content_matches.extend(matches)
        if len(content_matches) > 500:
            raise ManifestError("Content-script matches contain too many entries.")
    return {
        "raw": manifest,
        "name": name.strip(),
        "version": version,
        "manifest_version": manifest_version,
        "description": description.strip(),
        "permissions": permissions,
        "optional_permissions": optional_permissions,
        "host_permissions": host_permissions,
        "optional_host_permissions": optional_host_permissions,
        "content_matches": list(dict.fromkeys(content_matches)),
    }


def _is_broad_pattern(pattern):
    if pattern in BROAD_HOSTS:
        return True
    try:
        parsed = urlparse(pattern)
        return (
            parsed.hostname == "*"
            or bool(parsed.hostname and parsed.hostname.startswith("*."))
            or parsed.netloc == "*"
            or parsed.path == "/*" and parsed.hostname in (None, "")
        )
    except ValueError:
        return False


def analyze_manifest(parsed, purpose="", thresholds=None, risk_weights=None, permission_weights=None):
    thresholds = thresholds or {"low": 24, "moderate": 49, "high": 74}
    risk_weights = risk_weights or {"permission_sensitivity": 45, "host_scope": 25, "permission_combinations": 20, "purpose_alignment": 10}
    permission_weights = permission_weights or {}
    permissions = parsed["permissions"]
    optional = parsed["optional_permissions"]
    hosts = parsed["host_permissions"]
    optional_hosts = parsed["optional_host_permissions"]
    matches = parsed["content_matches"]
    broad_hosts = [host for host in hosts if _is_broad_pattern(host)]
    broad_optional_hosts = [host for host in optional_hosts if _is_broad_pattern(host)]
    broad_matches = [host for host in matches if _is_broad_pattern(host)]
    all_names = list(dict.fromkeys(permissions + optional + hosts + optional_hosts + matches))
    permission_details = []
    permission_points = 0
    findings = []
    for permission in permissions + optional:
        catalog = PERMISSION_CATALOG.get(permission)
        if catalog:
            category, capability, impact, action, weight = catalog
        elif permission.startswith(("http://", "https://", "*://")) or permission == "<all_urls>":
            category, capability, impact, action, weight = ("high" if _is_broad_pattern(permission) else "medium", "Grants access to matching web origins.", "Page access may include sensitive site content.", "Limit the origin pattern to the specific sites needed.", 0)
        else:
            category, capability, impact, action, weight = ("review", "Requests a browser capability not covered by the built-in catalog.", "The effect depends on the browser API and extension behavior.", "Review the relevant Chrome API documentation and feature need.", 2)
        weight = permission_weights.get(permission, weight)
        source = "optional" if permission in optional else "required"
        detail = {"name": permission, "source": source, "category": category, "capability": capability, "privacy_impact": impact, "why_it_matters": f"This permission is declared as {source} in the manifest.", "recommended_action": action, "weight": weight}
        permission_details.append(detail)
        if source == "required":
            permission_points += weight
        if category in ("high", "review"):
            findings.append({"kind": "permission", "severity": category, "title": f"{permission} permission requires attention", "evidence": f"Manifest permissions includes '{permission}'." if source == "required" else f"Manifest optional_permissions includes '{permission}'.", "explanation": impact, "recommendation": action})
    for permission, source in (
        *((host, "host_permissions") for host in hosts),
        *((host, "optional_host_permissions") for host in optional_hosts),
        *((host, "content_scripts.matches") for host in matches),
    ):
        broad = _is_broad_pattern(permission)
        permission_details.append({
            "name": permission, "source": source, "category": "high" if broad else "medium",
            "capability": "Grants page access to matching sites." if source != "content_scripts.matches" else "Runs declared content scripts on matching sites.",
            "privacy_impact": "A broad origin pattern may cover many or all sites." if broad else "Access is limited to the declared matching origins.",
            "why_it_matters": f"Declared under {source}.", "recommended_action": "Replace broad access with specific origins and request optional access when possible." if broad else "Confirm each origin is needed for the extension's declared purpose.",
            "weight": 0,
        })
    broad_points = min(risk_weights["host_scope"], len(broad_hosts) * 18 + len(broad_optional_hosts) * 9 + len(broad_matches) * 9)
    if broad_hosts or broad_optional_hosts or broad_matches:
        evidence = {"required_hosts": broad_hosts, "optional_hosts": broad_optional_hosts, "content_script_matches": broad_matches}
        findings.append({"kind": "host_scope", "severity": "high", "title": "Broad host access declared", "evidence": evidence, "explanation": "One or more origin patterns match a broad set of websites.", "recommendation": "Narrow host patterns to known required sites and consider optional host permissions."})
    effective = set(permissions)
    effective.update(optional)
    effective.update(hosts)
    effective.update(matches)
    has_broad = bool(broad_hosts or broad_optional_hosts or broad_matches)
    combinations = []
    for rule in COMBINATION_RULES:
        if rule["permissions"].issubset(effective) and (not rule.get("broad_host") or has_broad):
            optional_only = not rule["permissions"].issubset(set(permissions)) or bool(broad_optional_hosts and not (broad_hosts or broad_matches) and rule.get("broad_host"))
            combinations.append({"id": rule["id"], "title": rule["title"], "permissions": sorted(rule["permissions"]), "explanation": rule["explanation"], "potential_impact": rule["impact"], "evidence": {"permissions": sorted(rule["permissions"] & effective), "broad_hosts": broad_hosts + broad_optional_hosts + broad_matches, "requires_optional_grant": optional_only}, "recommended_action": rule["mitigation"], "weight": rule["weight"], "requires_optional_grant": optional_only})
    combination_points = min(risk_weights["permission_combinations"], sum(round(item["weight"] * 0.5) if item["requires_optional_grant"] else item["weight"] for item in combinations))
    purpose_findings = []
    purpose_points = 0
    host_sources = {"host_permissions", "optional_host_permissions", "content_scripts.matches"}
    broad_purpose_terms = ("all sites", "all websites", "every site", "every website", "all pages", "across websites")
    if purpose.strip():
        purpose_lower = purpose.lower()
        for detail in permission_details:
            permission = detail["name"]
            source = detail["source"]
            if source in host_sources:
                broad = _is_broad_pattern(permission)
                if broad:
                    scope_described = any(term in purpose_lower for term in broad_purpose_terms)
                    status = "review" if scope_described or source == "optional_host_permissions" else "requires_justification"
                    if status == "requires_justification":
                        purpose_points += 3
                    explanation = "The purpose mentions broad site access; an analyst should still verify each affected origin." if scope_described else "The purpose does not clearly justify this broad origin scope. Analyst review is needed; this does not establish that the access is unnecessary."
                else:
                    status = "review"
                    explanation = "Compare this declared origin with the extension's intended site-specific features."
                purpose_findings.append({"permission": permission, "status": status, "explanation": explanation, "source": source})
                continue
            if source not in ("required", "optional"):
                continue
            keywords = PURPOSE_KEYWORDS.get(permission)
            if keywords is None:
                status = "review"
                explanation = "There is not enough permission-specific purpose evidence for an automated relevance judgment."
            elif any(keyword in purpose_lower for keyword in keywords):
                status = "relevant"
                explanation = "Purpose text contains terms associated with this permission; this is a heuristic match, not proof of necessity."
            else:
                status = "requires_justification" if detail["category"] == "high" and detail["source"] == "required" else "review"
                explanation = "The purpose text does not clearly explain this permission. An analyst should verify the feature need; this result does not establish that the permission is unnecessary."
                if detail["source"] == "required" and detail["category"] in ("high", "review"):
                    purpose_points += 3
            purpose_findings.append({"permission": permission, "status": status, "explanation": explanation})
    else:
        purpose_findings = [
            {"permission": detail["name"], "status": "review", "explanation": "Provide the extension's declared purpose to assess alignment.", "source": detail["source"]}
            for detail in permission_details
        ]
    purpose_points = min(risk_weights["purpose_alignment"], purpose_points)
    permission_points = min(risk_weights["permission_sensitivity"], permission_points)
    score = min(100, permission_points + broad_points + combination_points + purpose_points)
    if score <= thresholds["low"]:
        risk = "low"
    elif score <= thresholds["moderate"]:
        risk = "moderate"
    elif score <= thresholds["high"]:
        risk = "high"
    else:
        risk = "critical"
    privacy_findings = [finding for finding in findings if finding["kind"] in {"permission", "host_scope"}]
    privacy_findings.extend({"kind": "combination", "severity": "review", "title": item["title"], "evidence": item["evidence"], "explanation": item["potential_impact"], "recommendation": item["recommended_action"]} for item in combinations)
    privacy_exposure_score = min(
        100,
        sum(detail["weight"] for detail in permission_details if detail["category"] == "high")
        + 15 * bool(broad_hosts or broad_optional_hosts or broad_matches)
        + min(20, len(combinations) * 5),
    )
    if purpose.strip() and purpose_findings:
        aligned = sum(item["status"] == "relevant" for item in purpose_findings)
        reviewable = sum(item["status"] == "review" for item in purpose_findings)
        purpose_alignment_score = round(100 * (aligned + reviewable * 0.5) / len(purpose_findings))
    else:
        purpose_alignment_score = None
    if parsed["manifest_version"] == 2:
        findings.append({"kind": "manifest", "severity": "review", "title": "Manifest Version 2", "evidence": {"manifest_version": 2}, "explanation": "Manifest V2 is deprecated by Chrome and may not be accepted for new extensions.", "recommendation": "Migrate to Manifest V3 and verify behavior against current Chrome documentation."})
    return {
        "permissions": {"required": permissions, "optional": optional, "host": hosts, "optional_host": optional_hosts, "content_matches": matches, "all": all_names},
        "permission_details": permission_details,
        "findings": findings,
        "combinations": combinations,
        "purpose_findings": purpose_findings,
        "privacy_findings": privacy_findings,
        "score_breakdown": {
            "permission_sensitivity": permission_points,
            "host_scope": broad_points,
            "permission_combinations": combination_points,
            "purpose_alignment": purpose_points,
            "raw_score": score,
            "method": "Sum of capped sensitivity (45), host scope (25), combinations (20), and purpose review (10) contributions. Combination points represent co-occurrence context; optional-only combinations contribute half weight until granted. This is a relative review-priority score, not a probability of malware.",
            "thresholds": thresholds,
        },
        "risk_score": score,
        "risk_level": risk,
        "requires_review": bool(findings or any(item["status"] == "review" for item in purpose_findings)),
        "privacy_exposure_score": privacy_exposure_score,
        "purpose_alignment_score": purpose_alignment_score,
    }
