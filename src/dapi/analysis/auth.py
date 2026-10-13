"""Authentication flow analysis.

All conclusions are derived from *secret sightings*: every place a vaulted
value appeared, in which flow, on which side. Because secret references are
deterministic, a token issued in a login response (``body:$.access_token``)
and later presented in ``Authorization: Bearer`` share a reference, which is
the evidence that links the two.
"""

from __future__ import annotations

import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl

from dapi.analysis.catalog import Catalog, Endpoint, flow_rejected_for_auth, flow_succeeded, parse_json
from dapi.models import Exchange, header_get, is_form_type
from dapi.store import Sighting
from dapi.vault import Vault

LOGOUT_RE = re.compile(r"(?i)(log[-_]?out|sign[-_]?out|revoke)")
REFRESH_PATH_RE = re.compile(r"(?i)refresh|/token$")
LOGIN_PATH_RE = re.compile(r"(?i)(log[-_]?in|sign[-_]?in|auth(enticate)?|session|oauth|token)")
PRESENTATION_PREFIXES = ("header:", "cookie:", "query:")
NON_CREDENTIAL_KINDS = {"username", "password"}
REFRESH_WINDOW_S = 120.0


def mechanism_type(location: str, scheme: str | None, kind: str) -> str:
    if location.lower() == "header:authorization":
        return {"bearer": "bearer", "basic": "basic"}.get((scheme or "").lower(), "authorization_header")
    if location.startswith("cookie:"):
        return "cookie"
    if location.startswith("query:"):
        return "query_token"
    if kind == "csrf":
        return "csrf_header"
    if kind == "api_key":
        return "api_key_header"
    return "header_token"


@dataclass
class AuthContext:
    """Pre-indexed view of flows and secret sightings used by auth, session and codegen logic."""

    flows: dict[int, Exchange]
    catalog: Catalog
    vault: Vault
    by_flow: dict[int, list[Sighting]]
    by_ref: dict[str, list[Sighting]]
    metas: dict[str, dict[str, Any]] = field(default_factory=dict)
    first_issue: dict[str, Sighting] = field(default_factory=dict)
    _presentations: dict[int, list[Sighting]] = field(default_factory=dict)

    @classmethod
    def build(
        cls, flows: list[Exchange], catalog: Catalog, sightings: list[Sighting], vault: Vault
    ) -> AuthContext:
        by_flow: dict[int, list[Sighting]] = defaultdict(list)
        by_ref: dict[str, list[Sighting]] = defaultdict(list)
        fmap = {f.id: f for f in flows}
        for s in sightings:
            if s.flow_id in fmap:
                by_flow[s.flow_id].append(s)
                by_ref[s.ref].append(s)
        first_issue: dict[str, Sighting] = {}
        for ref, refs in by_ref.items():
            refs.sort(key=lambda s: (fmap[s.flow_id].ts, s.flow_id))
            first = next((s for s in refs if s.side == "response"), None)
            if first is not None:
                first_issue[ref] = first
        metas = {m["ref"]: m for m in vault.list()}
        return cls(fmap, catalog, vault, by_flow, by_ref, metas, first_issue)

    # -- primitives ------------------------------------------------------------------------
    def meta(self, ref: str) -> dict[str, Any]:
        if ref not in self.metas:
            self.metas[ref] = self.vault.meta(ref)
        return self.metas[ref]

    def kind(self, ref: str) -> str:
        return self.meta(ref).get("kind", "secret")

    def presentations(self, flow_id: int) -> list[Sighting]:
        """Credential presentations in a request: auth headers, cookies, query tokens."""
        cached = self._presentations.get(flow_id)
        if cached is None:
            cached = [
                s
                for s in self.by_flow.get(flow_id, [])
                if s.side == "request"
                and s.location.startswith(PRESENTATION_PREFIXES)
                and self.kind(s.ref) not in NON_CREDENTIAL_KINDS
            ]
            self._presentations[flow_id] = cached
        return cached

    def issue(self, ref: str) -> Sighting | None:
        """The first response that carried this secret (where the client obtained it)."""
        return self.first_issue.get(ref)

    def latest_in_lineage(self, ref: str) -> str:
        """Follow credential rotation: newest secret issued at the same response location as ``ref``."""
        first = self.issue(ref)
        if first is None:
            return ref
        issuer = self.flows[first.flow_id]
        best, best_key = ref, (issuer.ts, issuer.id)
        for other_ref, sights in self.by_ref.items():
            for s in sights:
                if s.side != "response" or s.location != first.location:
                    continue
                f = self.flows[s.flow_id]
                if f.origin != issuer.origin:
                    continue
                if (f.ts, f.id) > best_key:
                    best, best_key = other_ref, (f.ts, f.id)
        return best

    def latest_issued(self, origin: str, kind: str) -> str | None:
        """Most recently issued secret of ``kind`` from a response on ``origin``."""
        best, best_key = None, None
        for ref, sights in self.by_ref.items():
            if self.kind(ref) != kind:
                continue
            for s in sights:
                f = self.flows[s.flow_id]
                if (
                    s.side == "response"
                    and f.origin == origin
                    and (best_key is None or (f.ts, f.id) > best_key)
                ):
                    best, best_key = ref, (f.ts, f.id)
        return best

    def endpoint_of(self, flow_id: int) -> Endpoint | None:
        ep_id = self.catalog.flow_endpoint.get(flow_id)
        return self.catalog.get(ep_id) if ep_id else None

    def scheme_of(self, flow: Exchange, location: str) -> str | None:
        if location.startswith("header:"):
            value = header_get(flow.req_headers, location.split(":", 1)[1]) or ""
            if value and not value.startswith("{{"):
                return value.split(" ", 1)[0]
        return None


def _lifetime(meta: dict[str, Any]) -> tuple[float | None, str | None]:
    jwt = meta.get("jwt") or {}
    if isinstance(jwt.get("exp"), int | float) and isinstance(jwt.get("iat"), int | float):
        return float(jwt["exp"] - jwt["iat"]), "jwt exp - iat"
    if isinstance(meta.get("expires_in"), int | float):
        return float(meta["expires_in"]), "expires_in field"
    attrs = meta.get("cookie_attrs") or {}
    if isinstance(attrs.get("max_age"), int):
        return float(attrs["max_age"]), "Set-Cookie Max-Age"
    if attrs.get("expires"):
        return None, f"Set-Cookie Expires={attrs['expires']}"
    return None, None


def _body_field(flow: Exchange, location: str) -> Any:
    """Read a non-secret value (e.g. grant_type) from a redacted request body."""
    if is_form_type(flow.req_content_type):
        return dict(parse_qsl(flow.req_body or "")).get(location)
    data = parse_json(flow.req_body)
    return data.get(location) if isinstance(data, dict) else None


def _ep_ref(ep: Endpoint | None) -> dict[str, Any]:
    if ep is None:
        return {"endpoint_id": None, "endpoint": "(unknown)"}
    op = f" ({ep.graphql['operation_type']} {ep.graphql['operation_name']})" if ep.graphql else ""
    return {"endpoint_id": ep.id, "endpoint": f"{ep.method} {ep.origin}{ep.path_template}{op}"}


def analyze_auth(ctx: AuthContext, origin: str | None = None) -> dict[str, Any]:
    flows = sorted(ctx.flows.values(), key=lambda f: (f.ts, f.id))
    endpoints = ctx.catalog.for_origin(origin)
    origins = sorted({e.origin for e in endpoints})
    report: dict[str, Any] = {"origins": {}}
    for org in origins:
        report["origins"][org] = _analyze_origin(ctx, org, [f for f in flows if f.origin == org])
    return report


def _analyze_origin(ctx: AuthContext, origin: str, flows: list[Exchange]) -> dict[str, Any]:
    notes: list[str] = []

    # 1. how credentials are presented ------------------------------------------------------
    mech: dict[str, dict[str, Any]] = {}
    for f in flows:
        for s in ctx.presentations(f.id):
            m = mech.setdefault(
                s.location,
                {
                    "location": s.location,
                    "scheme": ctx.scheme_of(f, s.location),
                    "kind": ctx.kind(s.ref),
                    "flows": [],
                    "endpoints": set(),
                    "refs": [],
                    "rejected_flows": [],
                },
            )
            m["flows"].append(f.id)
            ep_id = ctx.catalog.flow_endpoint.get(f.id)
            if ep_id:
                m["endpoints"].add(ep_id)
            if s.ref not in m["refs"]:
                m["refs"].append(s.ref)
            if f.status in (401, 403):
                m["rejected_flows"].append(f.id)

    mechanisms = []
    for loc, m in mech.items():
        issuers: dict[tuple, dict[str, Any]] = {}
        lifetimes: list[float] = []
        lifetime_sources: set[str] = set()
        unknown_origin = 0
        for ref in m["refs"]:
            first = ctx.issue(ref)
            meta = ctx.meta(ref)
            lt, src = _lifetime(meta)
            if lt is not None:
                lifetimes.append(lt)
            if src:
                lifetime_sources.add(src)
            if first is None:
                unknown_origin += 1
                continue
            ep = ctx.endpoint_of(first.flow_id)
            k = (ep.id if ep else None, first.location)
            item = issuers.setdefault(k, {**_ep_ref(ep), "location": first.location, "flows": []})
            item["flows"].append(first.flow_id)
        entry = {
            "type": mechanism_type(loc, m["scheme"], m["kind"]),
            "location": loc,
            **({"scheme": m["scheme"]} if m["scheme"] else {}),
            "used_in_flows": len(m["flows"]),
            "endpoints": len(m["endpoints"]),
            "distinct_values": len(m["refs"]),
            "issued_by": list(issuers.values()),
            "unknown_origin_values": unknown_origin,
            "rejected_flows": m["rejected_flows"][:10],
        }
        if lifetimes:
            entry["lifetime_seconds"] = statistics.median(lifetimes)
        if lifetime_sources:
            entry["lifetime_evidence"] = sorted(lifetime_sources)
        mechanisms.append(entry)
        for iss in entry["issued_by"]:
            notes.append(
                f"{loc} ({entry['type']}) values are issued by {iss['endpoint']} at {iss['location']} "
                f"(flows {', '.join('#' + str(x) for x in iss['flows'][:5])})."
            )
        if unknown_origin:
            notes.append(
                f"{loc}: {unknown_origin} value(s) were never seen being issued in captured traffic "
                "(obtained before capture started, issued by an out-of-scope host, or embedded in the app)."
            )
        if "lifetime_seconds" in entry:
            notes.append(
                f"{loc}: declared lifetime ~{int(entry['lifetime_seconds'])}s ({', '.join(sorted(lifetime_sources))})."
            )
    ablation = (ctx.vault.store.kv_get(f"ablation:{origin}") or {}).get("necessary", {})
    for m in mechanisms:
        if m["location"].lower() in {k.lower() for k in ablation}:
            m["necessary"] = next(v for k, v in ablation.items() if k.lower() == m["location"].lower())
            notes.append(
                f"{m['location']}: ablation test shows it is "
                + (
                    "REQUIRED"
                    if m["necessary"]
                    else "NOT required"
                    if m["necessary"] is False
                    else "inconclusive"
                )
                + " for authenticated requests."
            )
    mechanisms.sort(key=lambda m: (m.get("necessary") is False, -m["used_in_flows"]))

    # 2. login / refresh / logout endpoints ------------------------------------------------
    login: dict[str, dict[str, Any]] = {}
    refresh: dict[str, dict[str, Any]] = {}
    logout: dict[str, dict[str, Any]] = {}
    for f in flows:
        ep = ctx.endpoint_of(f.id)
        if ep is None:
            continue
        req_secrets = [s for s in ctx.by_flow.get(f.id, []) if s.side == "request"]
        issued = [s for s in ctx.by_flow.get(f.id, []) if s.side == "response"]
        kinds = {s.location: ctx.kind(s.ref) for s in req_secrets}
        grant_type = _body_field(f, "grant_type")
        has_password = any(k == "password" for k in kinds.values())
        body_refresh = [
            loc
            for loc, k in kinds.items()
            if k == "refresh_token" and not loc.startswith(("cookie:", "header:authorization"))
        ]
        if LOGOUT_RE.search(ep.path_template):
            item = logout.setdefault(ep.id, {**_ep_ref(ep), "flows": []})
            item["flows"].append(f.id)
            continue
        if has_password or grant_type in {"password", "client_credentials", "authorization_code"}:
            item = login.setdefault(
                ep.id,
                {
                    **_ep_ref(ep),
                    "flows": [],
                    "successful_flows": [],
                    "content_type": f.req_content_type,
                    "fields": {},
                    "issues": set(),
                    **({"grant_type": grant_type} if grant_type else {}),
                },
            )
            item["flows"].append(f.id)
            for loc, k in kinds.items():
                if loc.startswith(("body:", "form:")):
                    item["fields"][loc] = k
            if f.status and 200 <= f.status < 400:
                item["successful_flows"].append(f.id)
                item["issues"].update(s.location for s in issued)
        elif (
            body_refresh
            or grant_type == "refresh_token"
            or (REFRESH_PATH_RE.search(ep.path_template) and f.method == "POST" and issued)
        ):
            item = refresh.setdefault(
                ep.id,
                {
                    **_ep_ref(ep),
                    "flows": [],
                    "successful_flows": [],
                    "content_type": f.req_content_type,
                    "refresh_token_location": body_refresh[0] if body_refresh else None,
                    "issues": set(),
                    "rotates_refresh_token": False,
                },
            )
            item["flows"].append(f.id)
            if f.status and 200 <= f.status < 300:
                item["successful_flows"].append(f.id)
                item["issues"].update(s.location for s in issued)
                if any(ctx.kind(s.ref) == "refresh_token" for s in issued):
                    item["rotates_refresh_token"] = True
    for group in (login, refresh):
        for item in group.values():
            item["issues"] = sorted(item["issues"])
            ep = ctx.catalog.get(item["endpoint_id"])
            tag = "login" if group is login else "refresh"
            if ep and tag not in ep.tags:
                ep.tags.append(tag)
    for item in logout.values():
        ep = ctx.catalog.get(item["endpoint_id"])
        if ep and "logout" not in ep.tags:
            ep.tags.append("logout")
    for item in login.values():
        notes.append(
            f"Login: {item['endpoint']} accepts credentials in "
            f"{', '.join(sorted(item['fields'])) or 'the request'} and issues "
            f"{', '.join(item['issues']) or 'no captured credentials'}."
        )
    for item in refresh.values():
        notes.append(
            f"Refresh: {item['endpoint']} exchanges {item['refresh_token_location'] or 'a credential'} for "
            f"{', '.join(item['issues']) or 'new credentials'}"
            + (" and rotates the refresh token." if item["rotates_refresh_token"] else ".")
        )

    # 3. reactive refresh pattern: 401 -> refresh -> retry with a new credential -----------
    refresh_flow_ids = {fid for item in refresh.values() for fid in item["flows"]}
    reactive = []
    for i, f in enumerate(flows):
        if f.status != 401 or not ctx.presentations(f.id):
            continue
        for g in flows[i + 1 :]:
            if g.ts - f.ts > REFRESH_WINDOW_S:
                break
            if g.id in refresh_flow_ids:
                reactive.append({"rejected_flow": f.id, "refresh_flow": g.id})
                break
    if reactive:
        notes.append(f"Observed {len(reactive)} reactive refresh(es): a 401 followed by a refresh call.")

    # 4. CSRF: header values that were issued as cookies ----------------------------------
    csrf = []
    for m in mechanisms:
        if m["location"].startswith("header:"):
            for iss in m["issued_by"]:
                if iss["location"].startswith("set-cookie:") or m["type"] == "csrf_header":
                    csrf.append({"header": m["location"].split(":", 1)[1], "source": iss["location"]})
    for c in csrf:
        notes.append(f"CSRF: header {c['header']} echoes the value from {c['source']}.")

    # 5. per-endpoint auth requirement ------------------------------------------------------
    counts: dict[str, int] = defaultdict(int)
    for ep in ctx.catalog.for_origin(origin):
        ep_flows = [ctx.flows[i] for i in ep.flow_ids if i in ctx.flows]
        with_creds = [f for f in ep_flows if ctx.presentations(f.id)]
        without = [f for f in ep_flows if not ctx.presentations(f.id)]
        locs = sorted({s.location for f in with_creds for s in ctx.presentations(f.id)})
        ok_without = [f.id for f in without if flow_succeeded(f, ep)]
        denied_without = [f.id for f in without if flow_rejected_for_auth(f, ep)]
        denied_with = [f.id for f in with_creds if flow_rejected_for_auth(f, ep)]
        ok_with = [f.id for f in with_creds if flow_succeeded(f, ep)]
        if ok_without:
            required, evidence = "no", f"succeeded without credentials (flows {_ids(ok_without)})"
        elif denied_without:
            required, evidence = "yes", f"rejected without credentials (flows {_ids(denied_without)})"
        elif denied_with and ok_with:
            required, evidence = (
                "yes",
                (
                    f"rejected stale/invalid credentials (flows {_ids(denied_with)}) and accepted valid ones "
                    f"(flows {_ids(ok_with)})"
                ),
            )
        elif with_creds:
            required, evidence = (
                "likely",
                ("credentials were always sent; not yet confirmed (run session_verify with probe_auth=true)"),
            )
        else:
            required, evidence = "unknown", "no successful or rejected requests observed"
        if ("login" in ep.tags or "refresh" in ep.tags) and not denied_without:
            required, evidence = "no", "authentication endpoint: called to obtain credentials, not with them"
        ep.auth = {"required": required, "evidence": evidence, "credentials": locs}
        counts[required] += 1

    return {
        "mechanisms": mechanisms,
        "login": list(login.values()),
        "refresh": list(refresh.values()),
        "logout": list(logout.values()),
        "csrf": csrf,
        "reactive_refreshes": reactive[:10],
        "endpoint_auth_summary": dict(counts),
        "notes": notes,
    }


def _ids(ids: list[int]) -> str:
    shown = ", ".join(f"#{i}" for i in ids[:5])
    return shown + (f" +{len(ids) - 5} more" if len(ids) > 5 else "")
