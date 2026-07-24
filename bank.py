"""Persistent mock protected target implementing the EBAE Profile B contract.

The target authenticates executor proof-of-possession, signs every
authoritative response, commits balances/effects/idempotency atomically in
SQLite, and offers a signed status query for crash recovery.
"""

import os
import sqlite3
import tempfile

import ebae_core as E


class MockBank:
    target_id = "BANK-API"

    def __init__(
        self,
        db_path=None,
        authorized_executor_pub=None,
        *,
        key=None,
    ):
        if db_path is None:
            descriptor, db_path = tempfile.mkstemp(prefix="ebae_bank_", suffix=".db")
            os.close(descriptor)
        self.db_path = db_path
        self.authorized_executor_pub = authorized_executor_pub
        self.key = key or E.Signer("bank-target")
        self.pub = self.key.pub
        self.offline = False
        self.forge_next_response = False
        self._init_db()

    def _conn(self):
        connection = sqlite3.connect(
            self.db_path, timeout=30, isolation_level=None
        )
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _init_db(self):
        connection = self._conn()
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata(
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS balances(
                account TEXT PRIMARY KEY,
                amount INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS operations(
                operation_id TEXT PRIMARY KEY,
                request_digest TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transfers(
                operation_id TEXT PRIMARY KEY,
                payee TEXT NOT NULL,
                amount INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO metadata(key,value)
                VALUES('vendor_record_version',18);
            INSERT OR IGNORE INTO balances(account,amount)
                VALUES('OPS-1',100000);
            """
        )
        connection.close()

    @property
    def vendor_record_version(self):
        connection = self._conn()
        value = connection.execute(
            "SELECT value FROM metadata WHERE key='vendor_record_version'"
        ).fetchone()[0]
        connection.close()
        return value

    @vendor_record_version.setter
    def vendor_record_version(self, value):
        connection = self._conn()
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='vendor_record_version'",
            (value,),
        )
        connection.close()

    @property
    def balances(self):
        connection = self._conn()
        rows = connection.execute("SELECT account,amount FROM balances").fetchall()
        connection.close()
        return dict(rows)

    @property
    def transfers(self):
        connection = self._conn()
        rows = connection.execute(
            "SELECT operation_id,payee,amount FROM transfers ORDER BY rowid"
        ).fetchall()
        connection.close()
        return [
            {"op": operation_id, "payee": payee, "amount": amount}
            for operation_id, payee, amount in rows
        ]

    @property
    def operations(self):
        connection = self._conn()
        rows = connection.execute(
            "SELECT operation_id,request_digest,status FROM operations"
        ).fetchall()
        connection.close()
        return {
            operation_id: {"digest": digest, "status": status}
            for operation_id, digest, status in rows
        }

    def _proof_valid(
        self, proof, purpose, operation_id, request_digest, target_id
    ):
        if not isinstance(proof, dict):
            return False
        core = {
            "purpose": purpose,
            "operation_id": operation_id,
            "request_digest": request_digest,
            "target_id": target_id,
        }
        signature = proof.get("signature", {})
        return (
            proof.get("pub") == self.authorized_executor_pub
            and proof.get("core") == core
            and isinstance(signature, dict)
            and E.verify_sig(
                self.authorized_executor_pub,
                E.EXECUTOR_PROOF_DOMAIN,
                core,
                signature.get("sig", ""),
            )
        )

    def _signed(self, response):
        signed = dict(response)
        signed["target_signature"] = self.key.sign(
            E.TARGET_RESPONSE_DOMAIN, response
        )
        if self.forge_next_response:
            self.forge_next_response = False
            signature = signed["target_signature"]["sig"]
            signed["target_signature"]["sig"] = (
                ("00" if signature[:2] != "00" else "ff") + signature[2:]
            )
        return signed

    # ---- Profile B contract ----------------------------------------
    def invoke(self, request, proof):
        operation_id = request.get("operation_id")
        target_id = request.get("target_id")
        request_digest = E.H(E.REQUEST_DOMAIN, request)
        if target_id != self.target_id:
            return self._signed(
                {
                    "operation_id": operation_id,
                    "request_digest": request_digest,
                    "status": "DENIED",
                    "reason": "target_identity_mismatch",
                }
            )
        if not self._proof_valid(
            proof,
            "invoke",
            operation_id,
            request_digest,
            target_id,
        ):
            return self._signed(
                {
                    "operation_id": operation_id,
                    "request_digest": request_digest,
                    "status": "DENIED",
                    "reason": "executor_proof_invalid",
                }
            )
        if self.offline:
            raise ConnectionError("bank unreachable")
        amount = request.get("amount")

        connection = self._conn()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT request_digest,status FROM operations "
                "WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if existing is not None:
                connection.execute("COMMIT")
                if existing[0] != request_digest:
                    return self._signed(
                        {
                            "operation_id": operation_id,
                            "request_digest": request_digest,
                            "status": "REJECTED_DIGEST_CONFLICT",
                        }
                    )
                return self._signed(
                    {
                        "operation_id": operation_id,
                        "request_digest": request_digest,
                        "status": existing[1],
                    }
                )
            if not E._valid_amount(amount):
                connection.execute(
                    "INSERT INTO operations(operation_id,request_digest,status) "
                    "VALUES(?,?,'ABORTED')",
                    (operation_id, request_digest),
                )
                connection.execute("COMMIT")
                return self._signed(
                    {
                        "operation_id": operation_id,
                        "request_digest": request_digest,
                        "status": "ABORTED",
                        "reason": "invalid_amount",
                    }
                )

            wanted_version = request.get("conditions", {}).get(
                "vendor_record_version"
            )
            current_version = connection.execute(
                "SELECT value FROM metadata "
                "WHERE key='vendor_record_version'"
            ).fetchone()[0]
            account_row = connection.execute(
                "SELECT amount FROM balances WHERE account=?",
                (request.get("from_account"),),
            ).fetchone()
            if (
                (wanted_version is not None and wanted_version != current_version)
                or account_row is None
                or account_row[0] < amount
            ):
                connection.execute(
                    "INSERT INTO operations(operation_id,request_digest,status) "
                    "VALUES(?,?,'ABORTED')",
                    (operation_id, request_digest),
                )
                connection.execute("COMMIT")
                return self._signed(
                    {
                        "operation_id": operation_id,
                        "request_digest": request_digest,
                        "status": "ABORTED",
                    }
                )

            connection.execute(
                "UPDATE balances SET amount=amount-? WHERE account=?",
                (amount, request["from_account"]),
            )
            connection.execute(
                "INSERT INTO transfers(operation_id,payee,amount) VALUES(?,?,?)",
                (operation_id, request["payee"], amount),
            )
            connection.execute(
                "INSERT INTO operations(operation_id,request_digest,status) "
                "VALUES(?,?,'COMPLETED')",
                (operation_id, request_digest),
            )
            connection.execute("COMMIT")
            return self._signed(
                {
                    "operation_id": operation_id,
                    "request_digest": request_digest,
                    "status": "COMPLETED",
                }
            )
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        finally:
            connection.close()

    def query_status(self, operation_id, proof):
        if self.offline:
            return None
        if not isinstance(proof, dict):
            return self._signed(
                {
                    "operation_id": operation_id,
                    "request_digest": None,
                    "status": "DENIED",
                    "reason": "executor_proof_invalid",
                }
            )
        core = proof.get("core", {})
        expected_digest = core.get("request_digest")
        target_id = core.get("target_id")
        if target_id != self.target_id:
            return self._signed(
                {
                    "operation_id": operation_id,
                    "request_digest": None,
                    "status": "DENIED",
                    "reason": "target_identity_mismatch",
                }
            )
        if not self._proof_valid(
            proof,
            "query",
            operation_id,
            expected_digest,
            target_id,
        ):
            return self._signed(
                {
                    "operation_id": operation_id,
                    "request_digest": None,
                    "status": "DENIED",
                    "reason": "executor_proof_invalid",
                }
            )
        connection = self._conn()
        row = connection.execute(
            "SELECT request_digest,status FROM operations WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        connection.close()
        if row is None:
            return self._signed(
                {
                    "operation_id": operation_id,
                    "request_digest": None,
                    "status": "ABSENT",
                }
            )
        return self._signed(
            {
                "operation_id": operation_id,
                "request_digest": row[0],
                "status": row[1],
            }
        )


def make_intent(
    acd, payee="V-8841", amount=40_000, vendor_version=18
):
    """Untrusted planner stub; it never derives the operation identifier."""

    return {
        "intent_version": 1,
        "acd": acd,
        "action_class": "vendor_payment",
        "target_id": "BANK-API",
        "parameters": {
            "payee": payee,
            "amount": amount,
            "from_account": "OPS-1",
            "invoice": "2214",
        },
        "approvals": ["APPR-cfo-91", "APPR-controller-14"],
        "release_preconditions": {
            "vendor_record_version": vendor_version
        },
    }
