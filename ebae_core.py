"""EBAE software reference profile — reconstructed audit-remediated build.

This module implements the protocol mechanics described by Epoch-Bound
Attested Execution (EBAE): signed epoch manifests, deterministic
certification, single-use action certificates, durable reservations,
authenticated target release, recovery, rollback detection, and signed
receipts.

It is a protocol-logic reference implementation. It does not provide a
hardware monotonic counter, production key custody, replicated execution,
or a complete proof of the protocol state machine.
"""

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ---------------------------------------------------------------- canonical
def canon(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def H(domain: str, obj) -> str:
    h = hashlib.sha256()
    h.update(domain.encode() + b"\x00")
    h.update(obj if isinstance(obj, bytes) else canon(obj))
    return h.hexdigest()


class Reject(Exception):
    """Fail-closed rejection. ``reason`` identifies the failed check."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------- signing
class Signer:
    def __init__(self, name):
        self.name = name
        self._sk = Ed25519PrivateKey.generate()
        self.pub = self._sk.public_key().public_bytes_raw().hex()

    def sign(self, domain, obj):
        payload = domain.encode() + b"\x00" + canon(obj)
        return {"signer": self.name, "sig": self._sk.sign(payload).hex()}


def verify_sig(pub_hex, domain, obj, sig_hex):
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(
            bytes.fromhex(sig_hex),
            domain.encode() + b"\x00" + canon(obj),
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


# ---------------------------------------------------------------- domains
ACD_DOMAIN = "EBAE-AUTH-CLOSURE-v1"
MENV_DOMAIN = "EBAE-MANIFEST-ENVELOPE-v1"
CERT_DOMAIN = "EBAE-CERTIFICATE-v1"
RCPT_DOMAIN = "EBAE-RECEIPT-v1"
OP_DOMAIN = "EBAE-OP-v2"
INT_DOMAIN = "EBAE-INTENT-v1"
REQUEST_DOMAIN = "EBAE-REQUEST-v1"
EXECUTOR_PROOF_DOMAIN = "EBAE-EXECUTOR-PROOF-v1"
TARGET_RESPONSE_DOMAIN = "EBAE-TARGET-RESPONSE-v1"


def _valid_amount(value):
    """Amounts are strictly positive integers; bool is not an amount."""

    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def validate_signed_manifest(env, trust_root, *, check_expiry=True):
    """Validate the self-contained, threshold-signed manifest envelope."""

    try:
        body = env["body"]
        acd = env["acd"]
        if H(ACD_DOMAIN, body) != acd:
            raise Reject("acd_recompute_mismatch")
        core = {
            "acd": acd,
            "epoch_id": body["epoch_id"],
            "scope_id": body["scope_id"],
        }
        good = {
            sig["pub"]
            for sig in env["signatures"]
            if sig["pub"] in trust_root["authority_pubs"]
            and verify_sig(sig["pub"], MENV_DOMAIN, core, sig["sig"])
        }
        if len(good) < trust_root["quorum"]:
            raise Reject("quorum_not_met")
        if check_expiry and time.time() > body["expires_at"]:
            raise Reject("manifest_expired")
        return body
    except Reject:
        raise
    except (KeyError, TypeError, ValueError):
        raise Reject("manifest_malformed")


# ---------------------------------------------------------------- authority
class ManifestAuthority:
    """Threshold authority issuing epoch security manifests."""

    def __init__(self, signers, quorum):
        self.signers = signers
        self.quorum = quorum
        self.trust_root = {
            "authority_pubs": sorted(s.pub for s in signers),
            "quorum": quorum,
        }

    def issue(self, body, sign_with=None):
        acd = H(ACD_DOMAIN, body)
        env_core = {
            "acd": acd,
            "epoch_id": body["epoch_id"],
            "scope_id": body["scope_id"],
        }
        who = sign_with if sign_with is not None else self.signers[: self.quorum]
        return {
            "body": body,
            "acd": acd,
            "signatures": [
                {**signer.sign(MENV_DOMAIN, env_core), "pub": signer.pub}
                for signer in who
            ],
        }


def make_body(
    scope,
    epoch,
    prev_acd,
    *,
    policy_digest,
    validator_digest,
    certifier_pub,
    executor_scope,
    executor_pub,
    target_pub,
    payee_allow,
    tx_limit,
    state_floor=0,
    cert_ttl=600,
    expires_in=86400,
):
    now = int(time.time())
    return {
        "schema_version": 1,
        "scope_id": scope,
        "epoch_id": epoch,
        "previous_acd": prev_acd,
        "state_floor": state_floor,
        "issued_at": now,
        "expires_at": now + expires_in,
        "crypto_profiles": ["ed25519+sha256"],
        "policy_digest": policy_digest,
        "validator_digest": validator_digest,
        "certifier_pubs": [certifier_pub],
        "executor_constraints": {
            "scope": executor_scope,
            "executor_pub": executor_pub,
        },
        "action_classes": {
            "vendor_payment": {
                "payee_allowlist": payee_allow,
                "tx_limit": tx_limit,
                "approvals_required": 2,
                "max_cert_ttl": cert_ttl,
            }
        },
        "freshness_profile": "nonce+expiry",
        "target_operation_profiles": {
            "BANK-API": {
                "profile": "B_idempotent_conditional",
                "target_pub": target_pub,
            }
        },
        "transition_policy": {"orderly_drain": True},
    }


# ---------------------------------------------------------------- certifier
class Certifier:
    """Deterministic rules engine for one bounded action class."""

    def __init__(self, key: Signer, trust_root):
        self.key = key
        self.trust_root = trust_root

    def certify(self, intent, manifest):
        body = validate_signed_manifest(
            manifest, self.trust_root, check_expiry=True
        )
        if self.key.pub not in body["certifier_pubs"]:
            raise Reject("certifier_not_authorized")
        if intent["acd"] != manifest["acd"]:
            raise Reject("intent_acd_mismatch")
        rules = body["action_classes"].get(intent["action_class"])
        if rules is None:
            raise Reject("action_class_not_authorized")
        if intent["target_id"] not in body["target_operation_profiles"]:
            raise Reject("target_not_authorized")
        parameters = intent["parameters"]
        amount = parameters.get("amount")
        if not _valid_amount(amount):
            raise Reject("invalid_amount")
        if parameters["payee"] not in rules["payee_allowlist"]:
            raise Reject("payee_not_allowlisted")
        if amount > rules["tx_limit"]:
            raise Reject("amount_over_limit")
        if len(intent["approvals"]) < rules["approvals_required"]:
            raise Reject("insufficient_approvals")
        now = int(time.time())
        cert = {
            "certificate_id": secrets.token_hex(16),
            "one_time_nonce": secrets.token_hex(16),
            "acd": manifest["acd"],
            "epoch_id": body["epoch_id"],
            "intent_digest": H(INT_DOMAIN, intent),
            "policy_digest": body["policy_digest"],
            "validator_digest": body["validator_digest"],
            "executor_scope": body["executor_constraints"]["scope"],
            "target_id": intent["target_id"],
            "action_class": intent["action_class"],
            "granted_limit": amount,
            "release_preconditions": intent["release_preconditions"],
            "issued_at": now,
            "expires_at": min(
                body["expires_at"], now + rules["max_cert_ttl"]
            ),
            "max_uses": 1,
            "assurance_profile": "deterministic_replay",
        }
        cert["certifier_signature"] = self.key.sign(CERT_DOMAIN, cert)
        return cert


# ---------------------------------------------------------------- anchor
class MonotonicAnchor:
    """File-backed stand-in for a monotonic hardware mechanism.

    The file must live outside the executor database snapshot boundary.
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        if not os.path.exists(path):
            self._write(0)

    def _write(self, value):
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="ascii") as stream:
            stream.write(str(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, self.path)

    def read(self):
        with open(self.path, encoding="ascii") as stream:
            return int(stream.read())

    def advance_to(self, value):
        with self._lock:
            current = self.read()
            if value < current:
                raise Reject("anchor_regression")
            if value > current:
                self._write(value)


# ---------------------------------------------------------------- executor
class ProtectedExecutor:
    """Exclusive reference monitor for the protected target."""

    def __init__(
        self,
        db_path,
        anchor: MonotonicAnchor,
        trust_root,
        executor_key: Signer,
        scope_id,
    ):
        self.db_path = db_path
        self.anchor = anchor
        self.trust_root = trust_root
        self.key = executor_key
        self.scope_id = scope_id
        self.target = None
        self.safe_mode = False
        self.safe_reason = None
        self.receipts = []
        self._manifest = None
        self._safe_lock = threading.Lock()
        self._init_db()
        self._restore_state()

    # -- protected-state plumbing -----------------------------------
    def _conn(self):
        connection = sqlite3.connect(
            self.db_path, timeout=30, isolation_level=None
        )
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _init_db(self):
        connection = self._conn()
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scope_state(
                scope_id TEXT PRIMARY KEY,
                epoch_id INTEGER NOT NULL,
                acd TEXT NOT NULL,
                prev_acd TEXT,
                continuity_seq INTEGER NOT NULL,
                phase TEXT NOT NULL,
                safe_mode INTEGER NOT NULL DEFAULT 0,
                safe_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS staged(
                acd TEXT PRIMARY KEY,
                envelope TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS consumed(
                certificate_id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE,
                acd TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reservations(
                operation_id TEXT PRIMARY KEY,
                acd TEXT NOT NULL,
                cert_digest TEXT NOT NULL,
                intent_digest TEXT NOT NULL,
                target_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                request TEXT NOT NULL,
                certificate_expires_at INTEGER NOT NULL,
                continuity_seq INTEGER NOT NULL,
                phase TEXT NOT NULL,
                disposition TEXT,
                orphaned INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS receipts(
                operation_id TEXT PRIMARY KEY,
                receipt TEXT NOT NULL
            );
            """
        )
        # Minimal compatibility migration for a database created by v0.1.
        state_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(scope_state)")
        }
        if "safe_mode" not in state_columns:
            connection.execute(
                "ALTER TABLE scope_state ADD COLUMN safe_mode "
                "INTEGER NOT NULL DEFAULT 0"
            )
        if "safe_reason" not in state_columns:
            connection.execute(
                "ALTER TABLE scope_state ADD COLUMN safe_reason TEXT"
            )
        consumed_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(consumed)")
        }
        if "nonce" in consumed_columns:
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS consumed_nonce_unique "
                "ON consumed(nonce)"
            )
        reservation_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(reservations)")
        }
        if (
            reservation_columns
            and "certificate_expires_at" not in reservation_columns
        ):
            connection.execute(
                "ALTER TABLE reservations ADD COLUMN "
                "certificate_expires_at INTEGER NOT NULL DEFAULT 0"
            )
        connection.close()

    def _state(self, connection):
        row = connection.execute(
            "SELECT epoch_id,acd,prev_acd,continuity_seq,phase,"
            "safe_mode,safe_reason FROM scope_state WHERE scope_id=?",
            (self.scope_id,),
        ).fetchone()
        if row is None:
            return None
        keys = [
            "epoch_id",
            "acd",
            "prev_acd",
            "continuity_seq",
            "phase",
            "safe_mode",
            "safe_reason",
        ]
        return dict(zip(keys, row))

    def _restore_state(self):
        """Reload active authority, receipts, safety state, and continuity."""

        connection = self._conn()
        state = self._state(connection)
        receipt_rows = connection.execute(
            "SELECT receipt FROM receipts ORDER BY rowid"
        ).fetchall()
        self.receipts = [json.loads(row[0]) for row in receipt_rows]
        if state is None:
            connection.close()
            return
        self.safe_mode = bool(state["safe_mode"])
        self.safe_reason = state["safe_reason"]
        row = connection.execute(
            "SELECT envelope FROM staged WHERE acd=?", (state["acd"],)
        ).fetchone()
        connection.close()

        invalid_reason = None
        if row is None:
            invalid_reason = "active_manifest_missing"
        else:
            try:
                env = json.loads(row[0])
                self._validate_envelope(
                    env,
                    state["prev_acd"],
                    state=state,
                    check_expiry=False,
                    check_attached_target=False,
                )
                if (
                    env["acd"] != state["acd"]
                    or env["body"]["epoch_id"] != state["epoch_id"]
                ):
                    raise Reject("active_manifest_state_mismatch")
                self._manifest = env
            except (Reject, json.JSONDecodeError) as exc:
                invalid_reason = getattr(exc, "reason", "active_manifest_invalid")

        anchor_value = self.anchor.read()
        if state["continuity_seq"] > anchor_value:
            # The DB commit won but the process stopped before the anchor write.
            self.anchor.advance_to(state["continuity_seq"])
        elif state["continuity_seq"] < anchor_value:
            self._enter_safe_mode("rollback_detected", db_current=False)
        if invalid_reason is not None:
            self._enter_safe_mode(invalid_reason)

    def _startup_rollback_check(self):
        """Detect snapshot rollback: DB continuity behind the anchor."""

        connection = self._conn()
        state = self._state(connection)
        connection.close()
        db_seq = 0 if state is None else state["continuity_seq"]
        anchor_seq = self.anchor.read()
        if db_seq < anchor_seq or self.safe_reason == "rollback_detected":
            self._enter_safe_mode("rollback_detected", db_current=False)
            raise Reject("rollback_detected")
        if db_seq > anchor_seq:
            self.anchor.advance_to(db_seq)
        if self.safe_mode:
            raise Reject(f"safe_mode:{self.safe_reason}")
        return True

    def _enter_safe_mode(self, reason, db_current=True):
        """Persist fail-closed state and advance continuity when safe to do so."""

        with self._safe_lock:
            connection = self._conn()
            try:
                connection.execute("BEGIN IMMEDIATE")
                state = self._state(connection)
                if state is None:
                    connection.execute("ROLLBACK")
                    self.safe_mode = True
                    self.safe_reason = self.safe_reason or reason
                    return
                if state["safe_mode"]:
                    connection.execute("COMMIT")
                    self.safe_mode = True
                    self.safe_reason = state["safe_reason"] or reason
                    return
                current_enough = (
                    db_current
                    and state["continuity_seq"] >= self.anchor.read()
                )
                new_seq = (
                    state["continuity_seq"] + 1
                    if current_enough
                    else state["continuity_seq"]
                )
                connection.execute(
                    "UPDATE scope_state SET safe_mode=1,safe_reason=?,"
                    "continuity_seq=? WHERE scope_id=?",
                    (reason, new_seq, self.scope_id),
                )
                connection.execute("COMMIT")
                self.safe_mode = True
                self.safe_reason = reason
                if current_enough:
                    self.anchor.advance_to(new_seq)
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.OperationalError:
                    pass
                raise
            finally:
                connection.close()

    def _guard(self):
        if self.safe_mode:
            raise Reject(f"safe_mode:{self.safe_reason}")

    # -- manifest lifecycle ------------------------------------------
    def _validate_envelope(
        self,
        env,
        expect_prev,
        *,
        state=None,
        check_expiry=True,
        check_attached_target=True,
    ):
        body = validate_signed_manifest(
            env, self.trust_root, check_expiry=check_expiry
        )
        if body["scope_id"] != self.scope_id:
            raise Reject("scope_mismatch")
        if body["previous_acd"] != expect_prev:
            raise Reject("predecessor_mismatch")
        constraints = body.get("executor_constraints", {})
        if constraints.get("scope") != self.scope_id:
            raise Reject("executor_scope_mismatch")
        if constraints.get("executor_pub") != self.key.pub:
            raise Reject("executor_identity_mismatch")
        profiles = body.get("target_operation_profiles", {})
        for target_id, profile in profiles.items():
            if not isinstance(profile, dict) or not profile.get("target_pub"):
                raise Reject("target_identity_not_bound")
        if check_attached_target and self.target is not None:
            attached_profile = profiles.get(
                getattr(self.target, "target_id", None)
            )
            if (
                not isinstance(attached_profile, dict)
                or attached_profile.get("target_pub")
                != getattr(self.target, "pub", None)
            ):
                raise Reject("target_identity_mismatch")
        if state is not None:
            if body["epoch_id"] != state["epoch_id"]:
                raise Reject("epoch_state_mismatch")
            if env["acd"] != state["acd"]:
                raise Reject("acd_state_mismatch")
            if body["state_floor"] > state["continuity_seq"]:
                raise Reject("state_floor_unsatisfied")
        return body

    def _load_active_manifest(self, connection, *, check_expiry=True):
        state = self._state(connection)
        if state is None or state["phase"] != "ACTIVE":
            raise Reject("no_active_closure")
        row = connection.execute(
            "SELECT envelope FROM staged WHERE acd=?", (state["acd"],)
        ).fetchone()
        if row is None:
            raise Reject("active_manifest_missing")
        try:
            env = json.loads(row[0])
        except json.JSONDecodeError:
            raise Reject("active_manifest_malformed")
        self._validate_envelope(
            env,
            state["prev_acd"],
            state=state,
            check_expiry=check_expiry,
            check_attached_target=True,
        )
        if self.target is None:
            raise Reject("target_not_attached")
        profile = env["body"]["target_operation_profiles"].get(
            getattr(self.target, "target_id", None)
        )
        if (
            profile is None
            or profile["target_pub"] != getattr(self.target, "pub", None)
        ):
            raise Reject("target_identity_mismatch")
        self._manifest = env
        return state, env

    def stage_manifest(self, env):
        self._guard()
        connection = self._conn()
        state = self._state(connection)
        previous = state["acd"] if state else None
        self._validate_envelope(
            env,
            previous,
            check_expiry=True,
            check_attached_target=True,
        )
        if state and env["body"]["epoch_id"] <= state["epoch_id"]:
            connection.close()
            raise Reject("epoch_not_monotonic")
        current_sequence = state["continuity_seq"] if state else 0
        if env["body"]["state_floor"] > current_sequence:
            connection.close()
            raise Reject("state_floor_unsatisfied")
        connection.execute(
            "INSERT OR REPLACE INTO staged(acd,envelope) VALUES(?,?)",
            (env["acd"], canon(env).decode()),
        )
        connection.close()
        return env["acd"]

    def activate_manifest(self, acd, emergency=False):
        self._guard()
        connection = self._conn()
        try:
            connection.execute("BEGIN IMMEDIATE")
            state = self._state(connection)
            row = connection.execute(
                "SELECT envelope FROM staged WHERE acd=?", (acd,)
            ).fetchone()
            if row is None:
                raise Reject("not_staged")
            try:
                env = json.loads(row[0])
            except json.JSONDecodeError:
                raise Reject("staged_manifest_malformed")
            previous = state["acd"] if state else None
            self._validate_envelope(
                env,
                previous,
                check_expiry=True,
                check_attached_target=True,
            )
            if state and env["body"]["epoch_id"] <= state["epoch_id"]:
                raise Reject("epoch_not_monotonic")
            current_sequence = state["continuity_seq"] if state else 0
            if env["body"]["state_floor"] > current_sequence:
                raise Reject("state_floor_unsatisfied")
            open_rows = connection.execute(
                "SELECT operation_id FROM reservations WHERE phase!='CLOSED'"
            ).fetchall()
            if open_rows and not emergency:
                raise Reject("orderly_activation_blocked_by_open_reservations")
            if open_rows:
                connection.execute(
                    "UPDATE reservations SET orphaned=1 WHERE phase!='CLOSED'"
                )
            sequence = (state["continuity_seq"] if state else 0) + 1
            connection.execute(
                "INSERT OR REPLACE INTO scope_state("
                "scope_id,epoch_id,acd,prev_acd,continuity_seq,phase,"
                "safe_mode,safe_reason) VALUES(?,?,?,?,?,'ACTIVE',0,NULL)",
                (
                    self.scope_id,
                    env["body"]["epoch_id"],
                    acd,
                    previous,
                    sequence,
                ),
            )
            connection.execute("COMMIT")
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        finally:
            connection.close()
        self.anchor.advance_to(sequence)
        self._manifest = env
        self.safe_mode = False
        self.safe_reason = None
        return acd

    # -- ClosureComplete ---------------------------------------------
    def _closure_complete(self, connection, intent, cert):
        state, manifest = self._load_active_manifest(
            connection, check_expiry=True
        )
        body = manifest["body"]
        if not (intent["acd"] == cert["acd"] == state["acd"]):
            raise Reject("acd_mismatch")
        if cert["epoch_id"] != state["epoch_id"]:
            raise Reject("epoch_mismatch")
        if H(INT_DOMAIN, intent) != cert["intent_digest"]:
            raise Reject("intent_digest_mismatch")
        signature = cert["certifier_signature"]
        core = {
            key: value
            for key, value in cert.items()
            if key != "certifier_signature"
        }
        if not any(
            verify_sig(pub, CERT_DOMAIN, core, signature["sig"])
            for pub in body["certifier_pubs"]
        ):
            raise Reject("certifier_signature_invalid")
        if (
            cert["policy_digest"] != body["policy_digest"]
            or cert["validator_digest"] != body["validator_digest"]
        ):
            raise Reject("policy_or_validator_mismatch")
        if cert["executor_scope"] != self.scope_id:
            raise Reject("executor_scope_mismatch")
        if cert.get("max_uses") != 1:
            raise Reject("invalid_max_uses")
        if time.time() > cert["expires_at"]:
            raise Reject("certificate_expired")
        if cert["target_id"] != intent["target_id"]:
            raise Reject("target_id_mismatch")
        if cert["target_id"] not in body["target_operation_profiles"]:
            raise Reject("target_not_authorized")
        if (
            self.target is None
            or cert["target_id"] != getattr(self.target, "target_id", None)
        ):
            raise Reject("target_identity_mismatch")
        target_profile = body["target_operation_profiles"][cert["target_id"]]
        if target_profile.get("target_pub") != getattr(self.target, "pub", None):
            raise Reject("target_identity_mismatch")
        parameters = intent["parameters"]
        amount = parameters.get("amount")
        if not _valid_amount(amount):
            raise Reject("invalid_amount")
        rules = body["action_classes"].get(cert["action_class"])
        if rules is None:
            raise Reject("action_class_not_authorized")
        if (
            parameters["payee"] not in rules["payee_allowlist"]
            or amount > cert["granted_limit"]
            or amount > rules["tx_limit"]
        ):
            raise Reject("action_outside_certified_scope")
        return state

    # -- Reserve / Send / Close --------------------------------------
    def verify_and_reserve(self, intent, cert):
        self._guard()
        connection = self._conn()
        try:
            connection.execute("BEGIN IMMEDIATE")
            state = self._closure_complete(connection, intent, cert)
            operation_id = H(
                OP_DOMAIN,
                {
                    "acd": state["acd"],
                    "cert": H(CERT_DOMAIN, cert),
                    "intent": cert["intent_digest"],
                    "scope": self.scope_id,
                    "target": cert["target_id"],
                    "nonce": cert["one_time_nonce"],
                },
            )
            request = {
                "operation_id": operation_id,
                "target_id": cert["target_id"],
                "payee": intent["parameters"]["payee"],
                "amount": intent["parameters"]["amount"],
                "from_account": intent["parameters"]["from_account"],
                "conditions": cert["release_preconditions"],
            }
            request_digest = H(REQUEST_DOMAIN, request)
            try:
                connection.execute(
                    "INSERT INTO consumed(certificate_id,nonce,acd) "
                    "VALUES(?,?,?)",
                    (
                        cert["certificate_id"],
                        cert["one_time_nonce"],
                        state["acd"],
                    ),
                )
            except sqlite3.IntegrityError:
                cert_seen = connection.execute(
                    "SELECT 1 FROM consumed WHERE certificate_id=?",
                    (cert["certificate_id"],),
                ).fetchone()
                if cert_seen:
                    raise Reject("certificate_already_consumed")
                raise Reject("nonce_already_consumed")
            sequence = state["continuity_seq"] + 1
            connection.execute(
                "UPDATE scope_state SET continuity_seq=? WHERE scope_id=?",
                (sequence, self.scope_id),
            )
            connection.execute(
                "INSERT INTO reservations("
                "operation_id,acd,cert_digest,intent_digest,target_id,"
                "request_digest,request,certificate_expires_at,"
                "continuity_seq,phase,disposition,orphaned"
                ") VALUES(?,?,?,?,?,?,?,?,?,'PREPARED',NULL,0)",
                (
                    operation_id,
                    state["acd"],
                    H(CERT_DOMAIN, cert),
                    cert["intent_digest"],
                    cert["target_id"],
                    request_digest,
                    canon(request).decode(),
                    cert["expires_at"],
                    sequence,
                ),
            )
            connection.execute("COMMIT")
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        finally:
            connection.close()
        self.anchor.advance_to(sequence)
        return operation_id

    def _executor_proof(self, purpose, request):
        request_digest = H(REQUEST_DOMAIN, request)
        core = {
            "purpose": purpose,
            "operation_id": request["operation_id"],
            "request_digest": request_digest,
            "target_id": request["target_id"],
        }
        return {
            "pub": self.key.pub,
            "core": core,
            "signature": self.key.sign(EXECUTOR_PROOF_DOMAIN, core),
        }

    def _query_proof(self, operation_id, request_digest, target_id):
        core = {
            "purpose": "query",
            "operation_id": operation_id,
            "request_digest": request_digest,
            "target_id": target_id,
        }
        return {
            "pub": self.key.pub,
            "core": core,
            "signature": self.key.sign(EXECUTOR_PROOF_DOMAIN, core),
        }

    def send(self, operation_id, crash_after_send=False):
        self._guard()
        connection = self._conn()
        try:
            connection.execute("BEGIN IMMEDIATE")
            state, _manifest = self._load_active_manifest(
                connection, check_expiry=True
            )
            row = connection.execute(
                "SELECT request,phase,orphaned,acd,certificate_expires_at "
                "FROM reservations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise Reject("unknown_reservation")
            request = json.loads(row[0])
            phase, orphaned, reservation_acd, cert_expiry = (
                row[1],
                row[2],
                row[3],
                row[4],
            )
            if orphaned:
                raise Reject("reservation_orphaned")
            if phase != "PREPARED":
                raise Reject("not_prepared")
            if reservation_acd != state["acd"]:
                raise Reject("reservation_epoch_not_active")
            if (
                request.get("target_id")
                != getattr(self.target, "target_id", None)
            ):
                raise Reject("target_identity_mismatch")
            if cert_expiry and time.time() > cert_expiry:
                raise Reject("certificate_expired")
            sequence = state["continuity_seq"] + 1
            connection.execute(
                "UPDATE scope_state SET continuity_seq=? WHERE scope_id=?",
                (sequence, self.scope_id),
            )
            connection.execute(
                "UPDATE reservations SET phase='SENT',continuity_seq=? "
                "WHERE operation_id=?",
                (sequence, operation_id),
            )
            connection.execute("COMMIT")
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        finally:
            connection.close()

        # The externally durable anchor is advanced before target invocation.
        self.anchor.advance_to(sequence)
        proof = self._executor_proof("invoke", request)
        result = self.target.invoke(request, proof)
        if crash_after_send:
            return None
        return self._close(operation_id, result)

    def _target_pub_for(self, connection, acd, target_id):
        row = connection.execute(
            "SELECT envelope FROM staged WHERE acd=?", (acd,)
        ).fetchone()
        if row is None:
            raise Reject("reservation_manifest_missing")
        try:
            env = json.loads(row[0])
        except json.JSONDecodeError:
            raise Reject("reservation_manifest_malformed")
        body = validate_signed_manifest(
            env, self.trust_root, check_expiry=False
        )
        if body["scope_id"] != self.scope_id:
            raise Reject("scope_mismatch")
        if body["executor_constraints"].get("executor_pub") != self.key.pub:
            raise Reject("executor_identity_mismatch")
        profile = body["target_operation_profiles"].get(target_id)
        if not isinstance(profile, dict) or not profile.get("target_pub"):
            raise Reject("target_identity_not_bound")
        return profile["target_pub"]

    def _verify_target_response(
        self,
        connection,
        result,
        operation_id,
        request_digest,
        reservation_acd,
        target_id,
        *,
        allow_absent,
    ):
        if not isinstance(result, dict):
            raise Reject("forged_target_response")
        signature = result.get("target_signature")
        if not isinstance(signature, dict) or "sig" not in signature:
            raise Reject("forged_target_response")
        core = {
            key: value
            for key, value in result.items()
            if key != "target_signature"
        }
        target_pub = self._target_pub_for(
            connection, reservation_acd, target_id
        )
        if not verify_sig(
            target_pub, TARGET_RESPONSE_DOMAIN, core, signature["sig"]
        ):
            raise Reject("forged_target_response")
        if result.get("operation_id") != operation_id:
            raise Reject("target_digest_conflict")
        status = result.get("status")
        allowed = {"COMPLETED", "ABORTED"}
        if allow_absent:
            allowed.add("ABSENT")
        if status not in allowed:
            raise Reject("target_digest_conflict")
        if status == "ABSENT":
            if result.get("request_digest") is not None:
                raise Reject("target_digest_conflict")
        elif result.get("request_digest") != request_digest:
            raise Reject("target_digest_conflict")
        return status

    def _close(self, operation_id, result, recovery=False, internal=False):
        self._guard()
        connection = self._conn()
        metadata = connection.execute(
            "SELECT request_digest,acd,target_id FROM reservations "
            "WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if metadata is None:
            connection.close()
            raise Reject("unknown_reservation")
        request_digest, reservation_acd, target_id = metadata

        if result is None:
            new_disposition = "UNKNOWN"
        elif internal:
            new_disposition = result["status"]
        else:
            try:
                status = self._verify_target_response(
                    connection,
                    result,
                    operation_id,
                    request_digest,
                    reservation_acd,
                    target_id,
                    allow_absent=recovery,
                )
                # Signed, authoritative ABSENT proves no target effect.
                new_disposition = "ABORTED" if status == "ABSENT" else status
            except Reject as exc:
                connection.close()
                reason = (
                    "forged_target_response"
                    if exc.reason == "forged_target_response"
                    else "target_digest_conflict"
                )
                self._enter_safe_mode(reason)
                raise Reject(reason)

        if new_disposition not in {"COMPLETED", "ABORTED", "UNKNOWN"}:
            connection.close()
            raise Reject("invalid_disposition")

        created = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT phase,disposition FROM reservations "
                "WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            stored = connection.execute(
                "SELECT receipt FROM receipts WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if stored is not None:
                receipt = json.loads(stored[0])
                if receipt["disposition"] != new_disposition:
                    raise Reject("disposition_already_final")
                connection.execute("COMMIT")
                return receipt
            if row is None:
                raise Reject("unknown_reservation")
            if row[0] == "CLOSED":
                raise Reject("closed_without_receipt")
            if row[1] is not None and row[1] != new_disposition:
                raise Reject("disposition_already_final")
            state = self._state(connection)
            sequence = state["continuity_seq"] + 1
            receipt = {
                "operation_id": operation_id,
                "acd": reservation_acd,
                "disposition": new_disposition,
                "request_digest": request_digest,
                "continuity_after": sequence,
                "recovery": recovery,
            }
            receipt["executor_signature"] = self.key.sign(
                RCPT_DOMAIN, receipt
            )
            connection.execute(
                "UPDATE scope_state SET continuity_seq=? WHERE scope_id=?",
                (sequence, self.scope_id),
            )
            connection.execute(
                "UPDATE reservations SET phase='CLOSED',disposition=?,"
                "continuity_seq=? WHERE operation_id=?",
                (new_disposition, sequence, operation_id),
            )
            connection.execute(
                "INSERT INTO receipts(operation_id,receipt) VALUES(?,?)",
                (operation_id, canon(receipt).decode()),
            )
            connection.execute("COMMIT")
            created = True
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        finally:
            connection.close()

        self.anchor.advance_to(sequence)
        if created:
            self.receipts.append(receipt)
        return receipt

    # -- Recovery ------------------------------------------------------
    def recover(self, operation_id):
        """Recover without authorizing a second external effect."""

        self._guard()
        connection = self._conn()
        row = connection.execute(
            "SELECT phase,disposition,request,request_digest,target_id "
            "FROM reservations WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if row is None:
            connection.close()
            raise Reject("unknown_reservation")
        phase, _disposition, request_json, request_digest, target_id = row
        if phase == "CLOSED":
            stored = connection.execute(
                "SELECT receipt FROM receipts WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            connection.close()
            if stored is None:
                raise Reject("closed_without_receipt")
            return json.loads(stored[0])
        connection.close()

        if phase == "PREPARED":
            return self._close(
                operation_id,
                {"status": "ABORTED"},
                recovery=True,
                internal=True,
            )
        if phase != "SENT":
            raise Reject("invalid_reservation_phase")
        if self.target is None:
            raise Reject("target_not_attached")
        proof = self._query_proof(
            operation_id, request_digest, target_id
        )
        status = self.target.query_status(operation_id, proof)
        if status is None:
            return self._close(operation_id, None, recovery=True)
        return self._close(operation_id, status, recovery=True)

    def dump_reservations(self):
        connection = self._conn()
        rows = connection.execute(
            "SELECT operation_id,phase,disposition,orphaned "
            "FROM reservations ORDER BY rowid"
        ).fetchall()
        connection.close()
        return rows

    def receipt_count(self):
        connection = self._conn()
        count = connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        connection.close()
        return count
