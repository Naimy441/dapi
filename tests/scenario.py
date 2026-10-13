"""Shared traffic scenario: drives the demo API like a real client app would."""

from __future__ import annotations

import time

import httpx


def run_demo_session(client: httpx.Client, base: str, *, expire_wait: float = 0.0) -> None:
    """Login, browse, create a task, let the token expire, hit a 401, refresh, retry."""
    client.get(f"{base}/api/v1/public/health")
    client.get(f"{base}/api/v1/me")  # 401 before login
    tokens = client.post(
        f"{base}/api/v1/auth/login", json={"username": "demo", "password": "demo-password"}
    ).json()
    auth = {"Authorization": f"Bearer {tokens['access_token']}", "X-Client-Version": "4.2.0"}
    client.get(f"{base}/api/v1/me", headers=auth)
    projects = client.get(f"{base}/api/v1/projects", headers=auth).json()["items"]
    client.get(f"{base}/api/v1/projects", params={"archived": "false"}, headers=auth)
    for p in projects:
        client.get(f"{base}/api/v1/projects/{p['id']}", headers=auth)
        client.get(f"{base}/api/v1/projects/{p['id']}/tasks", params={"status": "open"}, headers=auth)
    client.post(
        f"{base}/api/v1/projects/{projects[0]['id']}/tasks", json={"title": "Write docs"}, headers=auth
    )
    if expire_wait:
        time.sleep(expire_wait)
        r = client.get(f"{base}/api/v1/me", headers=auth)
        assert r.status_code == 401, r.status_code
        tokens = client.post(
            f"{base}/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).json()
        auth["Authorization"] = f"Bearer {tokens['access_token']}"
        client.get(f"{base}/api/v1/me", headers=auth)
        client.get(f"{base}/api/v1/projects", headers=auth)


def run_web_session(client: httpx.Client, base: str) -> None:
    """Browser-like session against demo_web_app: CSRF cookie -> form login -> cookie-authenticated API."""
    client.get(f"{base}/api/profile")  # 403 before login
    page = client.get(f"{base}/login")
    token = page.text.split("name=csrfmiddlewaretoken value=")[1].split(">")[0]
    client.post(
        f"{base}/login", data={"username": "alice", "password": "wonderland", "csrfmiddlewaretoken": token}
    )
    client.get(f"{base}/api/profile")
    notes = client.get(f"{base}/api/notes").json()
    for n in notes:
        client.get(f"{base}/api/notes/{n['id']}")
    client.post(
        f"{base}/api/notes",
        json={"title": "New", "body": "x"},
        headers={"X-CSRFToken": client.cookies["csrftoken"]},
    )


VIEWER = "query Viewer {\n  viewer { id name projectCount }\n}"
PROJECT = "query Project($id: ID!) {\n  project(id: $id) { id name archived tasks { id title status } }\n}"
CREATE_TASK = "mutation CreateTask($projectId: ID!, $title: String!) {\n  createTask(projectId: $projectId, title: $title) { id title }\n}"


def run_graphql_session(client: httpx.Client, base: str) -> None:
    """A GraphQL client: unauthenticated query (errors-only 200), login, queries, a mutation."""
    url = f"{base}/api/graphql"
    client.post(url, json={"operationName": "Viewer", "query": VIEWER, "variables": {}})
    tokens = client.post(
        f"{base}/api/v1/auth/login", json={"username": "demo", "password": "demo-password"}
    ).json()
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    client.post(url, json={"operationName": "Viewer", "query": VIEWER, "variables": {}}, headers=auth)
    for pid in (101, 102):
        client.post(
            url, json={"operationName": "Project", "query": PROJECT, "variables": {"id": pid}}, headers=auth
        )
    client.post(
        url,
        json={
            "operationName": "CreateTask",
            "query": CREATE_TASK,
            "variables": {"projectId": 101, "title": "via graphql"},
        },
        headers=auth,
    )
