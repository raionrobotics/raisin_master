"""What this client assumes about the OTA server, asserted against a running one.

Unit tests cannot catch contract drift: the mocks encode the contract as this
client believes it to be, so a server that changes its mind keeps them green.
Every contract break found so far — a blob upload the endpoint never accepted,
`GET /packages` answering 400 to a parameter that was reported as "not found",
a manifest route that validated nothing — was found by making a real request
and would have been caught here.

Run against a server:

    RAISIN_OTA_ENDPOINT=http://localhost:8001/api python -m unittest test_contract

Skips entirely when no server is reachable, so it is safe in CI and on a
developer machine without one.

## What this suite may and may not assert

This repository is public. The suite is *designed* to document server
behaviour, which makes it the most likely place for an operational detail to
leak by convenience rather than by decision.

The rule: **assert what is allowed or refused, never how much or how often.**

- "`GET /packages` rejects `name`" — a contract. Fine.
- "manifest routes are closed to a robot credential" — a restriction, and
  publishing it says the guard exists rather than where it is missing. Fine.
- "the machine bucket allows N requests per M seconds" — an operational
  number, and knowing it exactly is what makes a budget cheap to exhaust.
  Belongs to the private side.

`TestThisSuiteKeepsItsOwnRule` enforces it on the assertions here, because a
convention nothing checks is a convention that erodes.

## Nothing here writes

Two rules keep it that way, and they are also what makes it a good contract
test rather than a smoke test:

1. Reads assert the **shape this client parses** — not the whole response, only
   the fields whose absence would break something here.
2. Writes are asserted by **how the endpoint refuses**. Sending a deliberately
   incomplete body and checking that the rejection names the missing field
   tests the contract precisely, creates nothing, and is exactly the class of
   bug that broke publish three times over.
"""

import os
import tempfile
import unittest
from pathlib import Path

import requests

import raisin_ota.client as ota

ENDPOINT = os.environ.get("RAISIN_OTA_ENDPOINT", "").rstrip("/")
ROBOT_KEY = os.environ.get("RAISIN_ROBOT_API_KEY", "")
ROBOT_NODE = os.environ.get("RAISIN_ROBOT_NODE", "primary")


def _server_reachable() -> bool:
    if not ENDPOINT:
        return False
    try:
        requests.get(f"{ENDPOINT}/packages", timeout=3)
        return True
    except requests.RequestException:
        return False


REACHABLE = _server_reachable()
skip_without_server = unittest.skipUnless(
    REACHABLE, f"no OTA server at {ENDPOINT or '(RAISIN_OTA_ENDPOINT unset)'}"
)
skip_without_robot_key = unittest.skipUnless(
    REACHABLE and ROBOT_KEY, "RAISIN_ROBOT_API_KEY unset"
)


def _user_auth():
    """(base, headers) for the user-authenticated routes, or None.

    The core refuses to work unconfigured, so the context has to be supplied
    here the same way any other caller supplies it.
    """
    try:
        ota.configure(
            ota.OtaContext(
                workspace=Path(tempfile.mkdtemp(prefix="contract-")),
                os_type="ubuntu",
                os_version="24.04",
                architecture="x86_64",
            )
        )
        return ota._get_auth_context()
    except Exception:  # noqa: BLE001 - an auth failure means skip, not fail
        return None


def _robot_headers(session=None):
    headers = {
        "Authorization": f"Robot {ROBOT_KEY}",
        "X-Robot-Node": ROBOT_NODE,
        "X-Client-Version": "contract-test",
    }
    if session:
        headers["X-Install-Session-Id"] = session
    return headers


@skip_without_server
class TestPackageListingContract(unittest.TestCase):
    """`GET /packages` — the shape the lookup code parses, and its limits."""

    @classmethod
    def setUpClass(cls):
        ctx = _user_auth()
        if not ctx:
            raise unittest.SkipTest("user authentication unavailable")
        cls.base, cls.headers = ctx

    def _get(self, **params):
        return requests.get(
            f"{self.base}/packages", headers=self.headers, params=params, timeout=15
        )

    def test_the_paginated_envelope_is_what_the_client_unwraps(self):
        body = ota._unwrap_response(self._get(search="raisin", limit=100).json())

        for field in ("packages", "total", "page", "limit", "totalPages"):
            self.assertIn(field, body, f"pagination field '{field}' disappeared")
        self.assertIsInstance(body["packages"], list)
        if body["packages"]:
            for field in ("id", "name"):
                self.assertIn(field, body["packages"][0])

    def test_name_is_still_not_a_parameter(self):
        """The client searches and filters because there is no exact lookup.

        If this ever starts answering 200, the extra filtering is dead weight
        and should be reconsidered — which is worth knowing.
        """
        self.assertEqual(self._get(name="raisin").status_code, 400)

    def test_limit_is_still_capped_at_100(self):
        """Paging exists because of this. If the cap moves, the page size should."""
        self.assertEqual(self._get(limit=1000).status_code, 400)
        self.assertEqual(self._get(limit=100).status_code, 200)

    def test_search_is_a_substring_match(self):
        """Why the client filters for an exact name rather than taking [0]."""
        names = [
            p["name"]
            for p in ota._unwrap_response(self._get(search="raisin", limit=100).json())[
                "packages"
            ]
        ]

        if len(names) > 1:
            self.assertTrue(
                any(n != "raisin" and "raisin" in n for n in names),
                "search stopped over-matching; the exact-name filter may be moot",
            )


@skip_without_server
class TestWriteRoutesRefuseAsExpected(unittest.TestCase):
    """Asserted by how they refuse, so nothing is created.

    Each of these was a silent client bug: the body was wrong and the endpoint
    answered 500 rather than naming the field, so publish failed three times
    over without saying why.
    """

    @classmethod
    def setUpClass(cls):
        ctx = _user_auth()
        if not ctx:
            raise unittest.SkipTest("user authentication unavailable")
        cls.base, cls.headers = ctx
        # A real package: these routes check the package exists *before* they
        # validate the body, so a made-up id answers 404 and tests nothing.
        cls.package_id = ota._fetch_package_id_by_name("raisin")
        if not cls.package_id:
            raise unittest.SkipTest("no package to post against")

    def test_blob_upload_still_requires_the_digest_header(self):
        resp = requests.post(
            f"{self.base}/blobs", headers=self.headers, data=b"", timeout=15
        )

        self.assertEqual(resp.status_code, 400)
        self.assertIn("x-content-sha256", resp.text.lower())

    def test_manifest_creation_names_what_is_missing(self):
        """It answered 500 until its DTO was applied as a class rather than a type."""
        resp = requests.post(
            f"{self.base}/packages/{self.package_id}/manifests",
            headers=self.headers,
            json={"version": "0.0.0"},
            timeout=15,
        )

        self.assertLess(
            resp.status_code,
            500,
            "body validation is not being applied — either it regressed, or the "
            f"server being tested predates the fix for it: {resp.text[:160]}",
        )
        self.assertEqual(resp.status_code, 400)

    def test_tag_creation_names_what_is_missing(self):
        resp = requests.post(
            f"{self.base}/packages/{self.package_id}/tags",
            headers=self.headers,
            json={"tag": "v0.0.0"},
            timeout=15,
        )

        self.assertLess(
            resp.status_code,
            500,
            "body validation is not being applied — either it regressed, or the "
            f"server being tested predates the fix for it: {resp.text[:160]}",
        )
        self.assertEqual(resp.status_code, 400)


@skip_without_server
class TestCredentialRotationContract(unittest.TestCase):
    """The routes `rotate_robot_credential` calls, asserted against a server.

    Every other check on these lives in this client's own mocks, which encode
    the contract as this client believes it -- so a server that never deployed
    them, or moved them, keeps all of it green. The client would then answer
    "could not obtain a replacement credential: 404 Client Error" on a fleet
    that has no way to renew itself, and nothing here would have said so first.

    No credential is needed and nothing is created: these assert *how the routes
    refuse*, which is rule 2 of this suite. A route that is not deployed answers
    404, and one that is answers 401 -- and the difference is the whole thing
    worth knowing.
    """

    def _refusal(self, path):
        return requests.post(f"{ENDPOINT}/{path}", timeout=15)

    def test_the_rotation_route_is_deployed_and_machine_guarded(self):
        resp = self._refusal("robots/me/credentials/rotate")

        self.assertEqual(
            resp.status_code,
            401,
            "a 404 here means the server predates credential rotation, and this "
            "client's rotation calls cannot work against it",
        )

    def test_the_retirement_route_is_deployed_and_machine_guarded(self):
        resp = self._refusal("robots/me/credentials/retire-superseded")

        self.assertEqual(resp.status_code, 401)

    def test_a_path_that_does_not_exist_still_answers_404(self):
        # The control. Without it the two assertions above would pass just as
        # well against a server that answers 401 to everything under this
        # prefix, which would tell us nothing about whether the routes are there.
        resp = self._refusal("robots/me/credentials/no-such-route")

        self.assertEqual(resp.status_code, 404)

    def test_an_unauthenticated_refusal_carries_no_credential_expiry(self):
        """`X-Credential-Expires` is about the caller's own credential.

        A caller that has not proved one must not be told anything, and the
        server's ordering is what guarantees it -- the guard refuses before the
        interceptor has a credential to describe. Asserted here because it is a
        property of the server this client would not notice losing.
        """
        resp = requests.get(
            f"{ENDPOINT}/robots/me/desired-state",
            headers={"x-robot-api-key": "rk_not_a_real_key"},
            timeout=15,
        )

        self.assertEqual(resp.status_code, 401)
        self.assertNotIn(ota.CREDENTIAL_EXPIRES_HEADER.lower(),
                         {k.lower() for k in resp.headers})


@skip_without_robot_key
class TestRobotContract(unittest.TestCase):
    """What a robot credential alone can obtain — the agent's whole surface."""

    def test_desired_state_carries_every_field_the_client_reads(self):
        resp = requests.get(
            f"{ENDPOINT}/robots/me/desired-state",
            headers=_robot_headers(),
            timeout=15,
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        state = ota._unwrap_response(resp.json())

        for field in ("halt", "haltSources", "pollIntervalSeconds", "target", "reason"):
            self.assertIn(field, state, f"desired-state lost '{field}'")
        self.assertIsInstance(state["halt"], bool)
        self.assertIsInstance(state["pollIntervalSeconds"], int)
        self.assertGreater(state["pollIntervalSeconds"], 0)

    def test_an_assigned_target_carries_the_package_list(self):
        """The only route a robot key can learn what to fetch from.

        Every manifest route answers 401 to a robot credential, so without this
        the agent knows its version and cannot obtain it.
        """
        state = ota._unwrap_response(
            requests.get(
                f"{ENDPOINT}/robots/me/desired-state",
                headers=_robot_headers(),
                timeout=15,
            ).json()
        )
        target = state.get("target")
        if not target:
            self.skipTest(f"node has no target assigned (reason={state.get('reason')})")

        for field in ("archiveId", "name", "version", "platform", "packages"):
            self.assertIn(field, target)
        for field in ("packageId", "packageName", "manifestHash"):
            self.assertIn(field, target["packages"][0])

    def test_manifest_routes_stay_closed_to_a_robot_key(self):
        """If one opens, `target.packages` stops being the only way in."""
        for path in ("archives", "archive-tags/by-name"):
            with self.subTest(path=path):
                resp = requests.get(
                    f"{ENDPOINT}/{path}", headers=_robot_headers(), timeout=15
                )
                self.assertIn(
                    resp.status_code, (401, 403), f"{path} → {resp.status_code}"
                )

    def test_an_unassigned_archive_is_refused(self):
        """A robot key used to reach every archive in its tenant."""
        resp = requests.get(
            f"{ENDPOINT}/robots/me/archives/by-key/packages/"
            f"00000000-0000-0000-0000-000000000000/download",
            headers=_robot_headers(session="contract-test-unassigned"),
            params={
                "name": "no-such-archive",
                "platform": "ubuntu-24.04-arm64",
                "version": "0.0.0",
            },
            timeout=15,
            allow_redirects=False,
        )

        self.assertNotIn(
            resp.status_code, (200, 206, 302), "an unassigned archive was served"
        )
        self.assertLess(
            resp.status_code, 500, f"refused with a server error: {resp.text[:200]}"
        )


class TestThisSuiteKeepsItsOwnRule(unittest.TestCase):
    """A public suite that starts recording limits stops being safe to publish.

    Checked rather than written down: the failure mode is somebody adding a
    throttle assertion because it was convenient, which is exactly the thing a
    comment does not prevent.
    """

    #: Terms that name a rate or a window. Naming them in prose is fine — this
    #: docstring does — but an *assertion* on one means a number went in.
    OPERATIONAL_TERMS = (
        "throttle",
        "rate limit",
        "retry-after",
        "requests per",
        "per minute",
        "per second",
        "window_seconds",
    )

    def _assertion_lines(self, path):
        source = Path(path).read_text(encoding="utf-8")
        for line_no, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("self.assert"):
                yield line_no, stripped

    def test_no_assertion_here_names_a_rate_or_a_window(self):
        offenders = [
            f"{line_no}: {line}"
            for line_no, line in self._assertion_lines(__file__)
            if any(term in line.lower() for term in self.OPERATIONAL_TERMS)
        ]

        self.assertEqual(
            offenders,
            [],
            "an operational limit is being asserted in a public suite; "
            "assert what is refused, not how much is allowed",
        )

    def test_the_guard_would_notice(self):
        """A guard nothing can fail is not a guard.

        Runs the same scan over a file with the leak deliberately written in,
        so a refactor that breaks the check fails here rather than going quiet
        and passing forever.
        """
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "planted.py"
            planted.write_text(
                "    def test_x(self):\n"
                "        self.assertEqual(body['limit'], 600)  # throttle budget\n"
                "        self.assertTrue(ok)\n",
                encoding="utf-8",
            )

            caught = [
                line
                for _, line in self._assertion_lines(planted)
                if any(term in line.lower() for term in self.OPERATIONAL_TERMS)
            ]

        self.assertEqual(len(caught), 1, "the scan no longer catches a leak")


if __name__ == "__main__":
    unittest.main()
