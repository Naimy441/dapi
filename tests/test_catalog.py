import json

from dapi.analysis.catalog import build_catalog, classify_segment, is_read_only
from dapi.analysis.schema import SchemaBuilder, check
from dapi.models import Exchange


def ex(i, method, path, status=200, body=None, query=None):
    return Exchange(
        id=i,
        ts=float(i),
        method=method,
        scheme="https",
        host="api.x.io",
        port=443,
        path=path,
        query=query or [],
        req_headers=[],
        req_body=None,
        req_content_type="",
        status=status,
        resp_headers=[],
        resp_body=json.dumps(body) if body is not None else None,
        resp_content_type="application/json" if body is not None else "",
    )


def test_classify_segment():
    assert classify_segment("123") == "integer"
    assert classify_segment("3f2b8c1e-9d4a-4f6b-8e2a-1c3d5e7f9a0b") == "uuid"
    assert classify_segment("5f9d88b1c2a3e4f5a6b7c8d9") == "hex"
    assert classify_segment("2026-01-02") == "date"
    assert classify_segment("users") is None
    assert classify_segment("v1") is None


def test_templating_ids_and_cardinality_merge():
    flows = [
        ex(1, "GET", "/api/users/1", body={"id": 1, "name": "a"}),
        ex(2, "GET", "/api/users/2", body={"id": 2, "name": "b"}),
        ex(3, "GET", "/api/orgs/acme/members", body=[{"id": 1}]),
        ex(4, "GET", "/api/orgs/globex/members", body=[{"id": 2}]),
        ex(5, "GET", "/api/orgs/initech/members", body=[{"id": 3}]),
        # different shapes: must stay separate literal endpoints
        ex(6, "GET", "/api/users", body={"items": []}),
        ex(7, "GET", "/api/orders", body={"orders": [], "next": None}),
        ex(8, "GET", "/api/products", body=[{"sku": "x"}]),
    ]
    cat = build_catalog(flows)
    paths = sorted(e.path_template for e in cat.endpoints)
    assert "/api/users/{user_id}" in paths
    assert "/api/orgs/{org}/members" in paths
    assert {"/api/users", "/api/orders", "/api/products"} <= set(paths)
    users = next(e for e in cat.endpoints if e.path_template == "/api/users/{user_id}")
    assert users.path_params[0]["examples"] == ["1", "2"]
    assert cat.flow_params[1] == {"user_id": "1"}


def test_query_params_and_schema():
    flows = [
        ex(
            1,
            "GET",
            "/s",
            query=[("q", "a"), ("page", "1")],
            body={"hits": [{"id": 1, "t": "2026-01-01T00:00:00Z"}]},
        ),
        ex(2, "GET", "/s", query=[("q", "b")], body={"hits": [], "cursor": None}),
    ]
    ep = build_catalog(flows).endpoints[0]
    assert ep.query_params["q"]["required"] and not ep.query_params["page"]["required"]
    assert ep.query_params["page"]["type"] == "integer"
    schema = ep.responses["200"]["schema"]
    assert schema["required"] == ["hits"]
    assert schema["properties"]["hits"]["items"]["properties"]["t"]["format"] == "date-time"
    assert schema["x-dapi-samples"] == 2


def test_read_only_classification():
    assert is_read_only("GET", "/users")[0]
    assert not is_read_only("GET", "/auth/logout")[0]
    assert not is_read_only("POST", "/users")[0]


def test_schema_merge_and_check():
    b = SchemaBuilder()
    b.add({"a": 1, "b": "x", "c": None})
    b.add({"a": 2.5, "c": {"d": True}})
    s = b.schema()
    assert s["properties"]["a"]["type"] == "number"
    assert s["required"] == ["a", "c"]
    assert s["properties"]["c"]["type"] == ["object", "null"]
    assert check(s, {"a": 3, "c": None}) == []
    assert check(s, {"a": "nope", "c": None})
    assert check(s, {"c": None})  # missing always-present key


def test_shared_envelope_collections_stay_separate():
    flows = [
        ex(1, "GET", "/v1/users", body={"data": [{"id": 1, "email": "a@b.co"}], "meta": {"page": 1}}),
        ex(
            2, "GET", "/v1/orders", body={"data": [{"id": 9, "total": 3.5, "lines": []}], "meta": {"page": 1}}
        ),
        ex(3, "GET", "/v1/products", body={"data": [{"sku": "x", "price": 1}], "meta": {"page": 1}}),
        ex(4, "GET", "/v1/users", body={"data": [{"id": 2, "email": "c@d.co"}], "meta": {"page": 2}}),
    ]
    paths = {e.path_template for e in build_catalog(flows).endpoints}
    assert paths == {"/v1/users", "/v1/orders", "/v1/products"}
