load("http",   "http")
load("json",   "json")
load("time",   "time")
load("log",    "log")
load("zafran", "zafran")


_CLOUD_ALLOWLIST = [
    "https://api.crowdstrike.com",
    "https://api.us-2.crowdstrike.com",
    "https://api.eu-1.crowdstrike.com",
    "https://api.laggar.gcw.crowdstrike.com",
]

_DEFAULT_VULN_FILTER = "created_timestamp:>'now-90d'+status:['open','reopen']"
_VULN_SORT           = "updated_timestamp.asc"
_PAGE_LIMIT_HOSTS    = 5000
_PAGE_LIMIT_VULNS    = 5000
_MAX_PAGES           = 2000

_MAX_RETRIES    = 5
_BACKOFF_BASE_S = 1
_BACKOFF_MAX_S  = 30

_INTEGRATION_NAME   = "crowdstrike_falcon"
_REMEDIATION_SOURCE = "CrowdStrike Spotlight"


def _is_known_cloud(api_url):
    for c in _CLOUD_ALLOWLIST:
        if api_url == c:
            return True
    return False

_HEX = "0123456789ABCDEF"
_BYTE_MAP = {
    " ":32, "!":33, "\"":34, "#":35, "$":36, "%":37, "&":38, "'":39, "(":40,
    ")":41, "*":42, "+":43, ",":44, "/":47, ":":58, ";":59, "<":60, "=":61,
    ">":62, "?":63, "@":64, "[":91, "\\":92, "]":93, "^":94, "`":96, "{":123,
    "|":124, "}":125,
}

def _percent_encode(s):
    out = []
    for i in range(len(s)):
        c = s[i]
        if (c >= "A" and c <= "Z") or (c >= "a" and c <= "z") or \
           (c >= "0" and c <= "9") or c == "-" or c == "_" or c == "." or c == "~":
            out.append(c)
            continue
        b = _BYTE_MAP.get(c)
        if b == None:
            continue
        out.append("%" + _HEX[b // 16] + _HEX[b % 16])
    return "".join(out)

def _sleep_backoff(attempt):
    delay = _BACKOFF_BASE_S * (1 << min(attempt, 5))
    if delay > _BACKOFF_MAX_S:
        delay = _BACKOFF_MAX_S
    time.sleep(time.parse_duration(str(delay) + "s"))


def _auth(api_url, client_id, client_secret):
    url  = api_url + "/oauth2/token"
    body = "client_id=" + _percent_encode(client_id) + \
           "&client_secret=" + _percent_encode(client_secret)
    resp = http.post(url,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
        body=body)
    sc = resp["status_code"]
    if sc != 200 and sc != 201:
        log.error("auth status=%d" % sc)
        fail("CrowdStrike OAuth2 failed (status=%d)" % sc)
    token = json.decode(resp["body"]).get("access_token")
    if not token:
        fail("CrowdStrike OAuth2 response missing access_token")
    return token

def _http_get_json(url, token_box, api_url, client_id, client_secret):
    for attempt in range(_MAX_RETRIES + 1):
        resp = http.get(url, headers={
            "Authorization": "Bearer " + token_box[0],
            "Accept": "application/json",
        })
        sc = resp["status_code"]

        if sc == 200:
            return json.decode(resp["body"])

        if sc == 401 and attempt == 0:
            log.warn("401 on %s — re-minting token" % url)
            token_box[0] = _auth(api_url, client_id, client_secret)
            continue

        if sc == 429 or (sc >= 500 and sc < 600):
            if attempt >= _MAX_RETRIES:
                log.error("giving up url=%s status=%d" % (url, sc))
                fail("CrowdStrike API failed after %d retries (status=%d)" % (_MAX_RETRIES, sc))
            log.warn("retrying url=%s attempt=%d status=%d" % (url, attempt + 1, sc))
            _sleep_backoff(attempt + 1)
            continue

        log.error("terminal error url=%s status=%d" % (url, sc))
        fail("CrowdStrike API returned %d (terminal)" % sc)

    fail("unreachable: exhausted retry loop")


def _paginate_hosts(api_url, token_box, client_id, client_secret, on_host, on_page_end):
    base   = api_url + "/devices/combined/devices/v1?limit=" + str(_PAGE_LIMIT_HOSTS)
    cursor = ""
    pages  = 0
    total  = 0

    for _ in range(_MAX_PAGES):
        url  = base + ("&offset=" + _percent_encode(cursor) if cursor else "")
        body = _http_get_json(url, token_box, api_url, client_id, client_secret)
        pages += 1

        resources  = body.get("resources", [])
        meta       = body.get("meta", {})
        pagination = meta.get("pagination", {})
        trace      = meta.get("trace_id", "")
        total     += len(resources)

        log.info("phase=hosts page=%d fetched=%d cumulative=%d trace_id=%s" % (
            pages, len(resources), total, trace))

        for h in resources:
            on_host(h)
        on_page_end({"pages": pages, "count": len(resources), "total": total})

        cursor = pagination.get("next", "")
        if not cursor or len(resources) < _PAGE_LIMIT_HOSTS:
            return total

    log.warn("hosts pagination hit _MAX_PAGES=%d safety cap" % _MAX_PAGES)
    return total

def _paginate_vulns(api_url, token_box, client_id, client_secret, fql_filter, on_vuln, on_page_end):
    base = (api_url + "/spotlight/combined/vulnerabilities/v1"
            + "?limit="  + str(_PAGE_LIMIT_VULNS)
            + "&sort="   + _percent_encode(_VULN_SORT)
            + "&facet=host_info&facet=cve&facet=remediation"
            + "&filter=" + _percent_encode(fql_filter))

    after = ""
    pages = 0
    total = 0

    for _ in range(_MAX_PAGES):
        url  = base + ("&after=" + _percent_encode(after) if after else "")
        body = _http_get_json(url, token_box, api_url, client_id, client_secret)
        pages += 1

        resources  = body.get("resources", [])
        meta       = body.get("meta", {})
        pagination = meta.get("pagination", {})
        trace      = meta.get("trace_id", "")
        total     += len(resources)

        log.info("phase=vulns page=%d fetched=%d cumulative=%d trace_id=%s" % (
            pages, len(resources), total, trace))

        for v in resources:
            on_vuln(v)
        on_page_end({"pages": pages, "count": len(resources), "total": total})

        after = pagination.get("after", "")
        if not after or len(resources) < _PAGE_LIMIT_VULNS:
            return total

    log.warn("vulns pagination hit _MAX_PAGES=%d safety cap" % _MAX_PAGES)
    return total


def _normalize_mac(mac):
    return mac.replace("-", ":").lower() if mac else ""

def _dedup_nonempty(values):
    out  = []
    seen = {}
    for v in values:
        if not v or v in seen:
            continue
        seen[v] = True
        out.append(v)
    return out

def _kv(pb, key, value):
    if value == None:
        return None
    sv = str(value)
    return pb.InstanceTagKeyValue(key=key, value=sv) if sv else None

def _label(pb, value):
    return pb.InstanceLabel(label=value) if value else None

def _cloud_identifier(pb, host):
    sp          = (host.get("service_provider") or "").upper()
    instance_id = host.get("instance_id") or ""
    if not sp or not instance_id:
        return None
    if sp == "AWS_EC2" or sp == "AWS" or sp == "AWS_EC2_V2":
        key = pb.IdentifierType.AWS_EC2_INSTANCE_ID
    elif sp == "AZURE":
        key = pb.IdentifierType.AZURE_VM_ID
    else:
        return None
    return pb.InstanceIdentifier(key=key, value=instance_id)

def _map_asset(pb, host):
    device_id = host.get("device_id") or ""
    if not device_id:
        return None

    hostname  = host.get("hostname") or device_id
    os_string = (host.get("platform_name") or "")
    if host.get("os_version"):
        os_string = (os_string + " " + host.get("os_version")).strip()
    if host.get("os_build"):
        os_string = (os_string + " (build " + host.get("os_build") + ")").strip()

    asset_info  = pb.AssetInstanceInformation(
        ip_addresses  = _dedup_nonempty([host.get("local_ip") or "", host.get("external_ip") or ""]),
        mac_addresses = _dedup_nonempty([_normalize_mac(host.get("mac_address") or "")]),
    )
    identifiers = [pb.InstanceIdentifier(key=pb.IdentifierType.CROWDSTRIKE_AID,
                                         value=device_id)]
    cloud_id = _cloud_identifier(pb, host)
    if cloud_id != None:
        identifiers.append(cloud_id)

    kv_pairs = []
    for k, v in [
        ("cid",                         host.get("cid")),
        ("machine_domain",              host.get("machine_domain")),
        ("site_name",                   host.get("site_name")),
        ("product_type_desc",           host.get("product_type_desc")),
        ("agent_version",               host.get("agent_version")),
        ("status",                      host.get("status")),
        ("first_seen",                  host.get("first_seen")),
        ("last_seen",                   host.get("last_seen")),
        ("kernel_version",              host.get("kernel_version")),
        ("system_manufacturer",         host.get("system_manufacturer")),
        ("system_product_name",         host.get("system_product_name")),
        ("bios_manufacturer",           host.get("bios_manufacturer")),
        ("bios_version",                host.get("bios_version")),
        ("service_provider",            host.get("service_provider")),
        ("service_provider_account_id", host.get("service_provider_account_id")),
    ]:
        kv = _kv(pb, k, v)
        if kv != None:
            kv_pairs.append(kv)

    for raw in (host.get("tags") or []):
        if raw.startswith("FalconGroupingTags/"):
            kv_pairs.append(pb.InstanceTagKeyValue(key="falcon_grouping_tag",
                value=raw[len("FalconGroupingTags/"):]))
        elif raw.startswith("SensorGroupingTags/"):
            kv_pairs.append(pb.InstanceTagKeyValue(key="sensor_grouping_tag",
                value=raw[len("SensorGroupingTags/"):]))
        else:
            kv_pairs.append(pb.InstanceTagKeyValue(key="falcon_tag", value=raw))

    labels = []
    for g in (host.get("groups") or []):
        name = (g.get("name") or g.get("id") or "") if type(g) == "dict" else str(g)
        lab  = _label(pb, name)
        if lab != None:
            labels.append(lab)

    return pb.InstanceData(instance_id=device_id, name=hostname,
        operating_system=os_string, asset_information=asset_info,
        identifiers=identifiers, labels=labels, key_value_tags=kv_pairs)

def _backfill_asset_from_vuln(pb, vuln):
    aid = vuln.get("aid") or ""
    if not aid:
        return None
    hi = vuln.get("host_info") or {}

    os_string = (hi.get("platform") or "")
    if hi.get("os_version"):
        os_string = (os_string + " " + hi.get("os_version")).strip()
    if hi.get("os_build"):
        os_string = (os_string + " (build " + hi.get("os_build") + ")").strip()

    kv_pairs = []
    for k, v in [
        ("cid",               vuln.get("cid")),
        ("machine_domain",    hi.get("machine_domain")),
        ("site_name",         hi.get("site_name")),
        ("product_type_desc", hi.get("product_type_desc")),
        ("asset_criticality", hi.get("asset_criticality")),
        ("internet_exposure", hi.get("internet_exposure")),
        ("managed_by",        hi.get("managed_by")),
        ("backfilled_from",   "spotlight_host_info"),
    ]:
        kv = _kv(pb, k, v)
        if kv != None:
            kv_pairs.append(kv)

    labels = []
    for g in (hi.get("groups") or []):
        name = g.get("name") if type(g) == "dict" else str(g)
        lab  = _label(pb, name)
        if lab != None:
            labels.append(lab)

    return pb.InstanceData(
        instance_id       = aid,
        name              = hi.get("hostname") or aid,
        operating_system  = os_string,
        asset_information = pb.AssetInstanceInformation(
            ip_addresses  = _dedup_nonempty([hi.get("local_ip") or ""]),
            mac_addresses = [],
        ),
        identifiers    = [pb.InstanceIdentifier(key=pb.IdentifierType.CROWDSTRIKE_AID,
                             value=aid)],
        labels         = labels,
        key_value_tags = kv_pairs,
    )

_OS_KEYWORDS = [
    "Windows", "Ubuntu", "Debian", "CentOS", "RedHat", "Red Hat",
    "Amazon Linux", "macOS", "Mac OS", "OS X", "SUSE",
]

def _component_type(pb, product_name):
    if not product_name:
        return pb.ComponentType.APPLICATION
    for kw in _OS_KEYWORDS:
        if product_name.find(kw) >= 0:
            return pb.ComponentType.OPERATING_SYSTEM
    low = product_name.lower()
    if low.startswith("lib") or low.startswith("openssl") or low.find(".so") >= 0:
        return pb.ComponentType.LIBRARY
    return pb.ComponentType.APPLICATION

def _cvss_version_from_vector(vector):
    if vector and vector.startswith("CVSS:"):
        rest = vector[5:]
        idx  = rest.find("/")
        if idx > 0:
            return rest[:idx]
    return "3.0"

def _remediation_suggestion(vuln):
    apps = vuln.get("apps") or []
    recommended_id = ""
    if len(apps) > 0:
        ri = apps[0].get("remediation_info") or {}
        recommended_id = ri.get("recommended_id") or ri.get("minimum_id") or ""

    for entity in ((vuln.get("remediation") or {}).get("entities") or []):
        if entity.get("id") == recommended_id:
            parts = []
            if entity.get("title"):
                parts.append(entity.get("title"))
            if entity.get("action") and entity.get("action") != entity.get("title"):
                parts.append(entity.get("action"))
            if entity.get("link"):
                parts.append(entity.get("link"))
            if parts:
                return " - ".join(parts)

    advisories = (vuln.get("cve") or {}).get("vendor_advisory") or []
    return ("See vendor advisory: " + advisories[0]) if len(advisories) > 0 \
        else "No remediation available"

def _map_vulnerability(pb, vuln):
    aid    = vuln.get("aid") or ""
    cve    = vuln.get("cve") or {}
    cve_id = cve.get("id") or vuln.get("vulnerability_id") or ""
    if not aid or not cve_id:
        return None

    apps    = vuln.get("apps") or []
    app0    = apps[0] if len(apps) > 0 else {}
    product = app0.get("product_name_normalized") or ""
    vendor  = app0.get("vendor_normalized") or ""
    version = app0.get("product_name_version") or ""

    cvss_list = []
    if cve.get("vector") or cve.get("base_score") != None:
        cvss_list.append(pb.CVSS(
            version    = _cvss_version_from_vector(cve.get("vector") or ""),
            vector     = cve.get("vector") or "",
            base_score = float(cve.get("base_score") or 0),
        ))

    return pb.Vulnerability(
        instance_id  = aid,
        cve          = cve_id,
        in_runtime   = (vuln.get("confidence") == "confirmed"),
        component    = pb.Component(
            type         = _component_type(pb, product),
            product      = product or cve_id,
            vendor       = vendor,
            version      = version,
            display_name = (product + " " + version).strip() or cve_id,
        ),
        remediation  = pb.Remediation(
            suggestion = _remediation_suggestion(vuln),
            source     = _REMEDIATION_SOURCE,
        ),
        CVSS        = cvss_list,
        description = cve.get("description") or cve.get("original_description") or "",
    )


def _on_host(host, pb, ctx):
    inst = _map_asset(pb, host)
    if inst == None:
        return
    zafran.collect_instance(inst)
    ctx["instances_cache"].append(inst)
    ctx["seen_aids"][host.get("device_id") or ""] = True
    ctx["host_counter"][0] += 1

def _on_host_page_end(stats, ctx):
    pass  # do not flush here — instances must stay in memory until vuln batches are flushed

def _on_vuln(v, pb, ctx):
    if v.get("status") == "expired":
        ctx["skipped_expired"][0] += 1
        return
    if (v.get("suppression_info") or {}).get("is_suppressed") == True:
        ctx["skipped_suppressed"][0] += 1
        return

    aid = v.get("aid") or ""
    if not aid:
        return

    if not ctx["seen_aids"].get(aid):
        bf = _backfill_asset_from_vuln(pb, v)
        if bf != None:
            zafran.collect_instance(bf)
            ctx["seen_aids"][aid] = True
            ctx["backfilled"][0] += 1
            log.warn("backfilled instance from host_info aid=%s" % aid)

    mapped = _map_vulnerability(pb, v)
    if mapped == None:
        return
    zafran.collect_vulnerability(mapped)
    ctx["vuln_counter"][0] += 1

def _on_vuln_page_end(stats, ctx):
    for inst in ctx["instances_cache"]:
        zafran.collect_instance(inst)
    zafran.flush()


def main(**kwargs):
    api_url       = kwargs.get("api_url", "")
    client_id     = kwargs.get("api_key", "")
    client_secret = kwargs.get("api_secret", "")

    if not api_url or not client_id or not client_secret:
        log.error("missing required parameters (api_url / api_key / api_secret)")
        fail("api_url, api_key and api_secret are required")

    if api_url.endswith("/"):
        api_url = api_url[:-1]

    if not _is_known_cloud(api_url):
        log.error("api_url=%s not in allowlist" % api_url)
        fail("api_url must be one of the documented CrowdStrike cloud base URLs")

    pb        = zafran.proto_file
    token_box = [_auth(api_url, client_id, client_secret)]
    log.info("crowdstrike: auth ok — pulling from %s" % api_url)

    ctx = {
        "seen_aids":          {},
        "instances_cache":    [],
        "host_counter":       [0],
        "vuln_counter":       [0],
        "skipped_expired":    [0],
        "skipped_suppressed": [0],
        "backfilled":         [0],
    }

    def on_host(host):           _on_host(host, pb, ctx)
    def on_host_page_end(stats): _on_host_page_end(stats, ctx)
    def on_vuln(v):              _on_vuln(v, pb, ctx)
    def on_vuln_page_end(stats): _on_vuln_page_end(stats, ctx)

    log.info("crowdstrike: phase=hosts starting")
    _paginate_hosts(api_url, token_box, client_id, client_secret,
                    on_host, on_host_page_end)
    log.info("crowdstrike: phase=hosts done count=%d" % ctx["host_counter"][0])

    log.info("crowdstrike: phase=vulns starting filter=%s" % _DEFAULT_VULN_FILTER)
    _paginate_vulns(api_url, token_box, client_id, client_secret,
                    _DEFAULT_VULN_FILTER, on_vuln, on_vuln_page_end)
    log.info("crowdstrike: phase=vulns done count=%d skipped_expired=%d skipped_suppressed=%d backfilled=%d" % (
        ctx["vuln_counter"][0], ctx["skipped_expired"][0],
        ctx["skipped_suppressed"][0], ctx["backfilled"][0]))

    log.info("crowdstrike: done hosts=%d vulns=%d" % (
        ctx["host_counter"][0], ctx["vuln_counter"][0]))
