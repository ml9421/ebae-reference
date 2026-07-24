"""EBAE v0.4 attack & fault matrix (White Paper Sec. 14.4) against the
software reference profile. Every test states the injected attack and the
required result. Exit code 0 only if all tests pass AND the count of
unauthorized external effects is zero."""
import os, sys, json, shutil, sqlite3, threading, tempfile, copy
sys.path.insert(0, os.path.dirname(__file__))
import ebae_core as E
from ebae_core import (Signer, ManifestAuthority, Certifier, ProtectedExecutor,
                       MonotonicAnchor, make_body, Reject, H)
from bank import MockBank, make_intent

RESULTS = []
def check(name, injection, ok, detail=""):
    RESULTS.append((name, injection, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL':4}  {name:28s} {detail}")

def expect_reject(fn, reason_substr):
    try:
        fn(); return False, "no rejection raised"
    except Reject as r:
        return (reason_substr in r.reason), f"rejected: {r.reason}"

def sqlite_snapshot(source_path, destination_path):
    source = sqlite3.connect(source_path)
    destination = sqlite3.connect(destination_path)
    source.backup(destination)
    destination.close()
    source.close()

def fresh_world(tmp):
    """Authority (2-of-3), certifier, executor, bank; epoch 41 active."""
    signers = [Signer(f"auth-{i}") for i in range(3)]
    authority = ManifestAuthority(signers, quorum=2)
    cert_key = Signer("certifier")
    exec_key = Signer("executor")
    anchor = MonotonicAnchor(os.path.join(tmp, "anchor.nv"))
    bank = MockBank(os.path.join(tmp, "bank.db"), exec_key.pub)
    ex = ProtectedExecutor(os.path.join(tmp, "state.db"), anchor,
                           authority.trust_root, exec_key, "PAY-GW-2")
    ex.target = bank
    certifier = Certifier(cert_key, authority.trust_root)
    body41 = make_body("PAY-GW-2", 41, None, policy_digest="P18",
                       validator_digest="V5", certifier_pub=cert_key.pub,
                       executor_scope="PAY-GW-2", executor_pub=exec_key.pub,
                       target_pub=bank.pub,
                       payee_allow=["V-8841", "V-2210"], tx_limit=50_000)
    m41 = authority.issue(body41)
    ex.activate_manifest(ex.stage_manifest(m41))
    return authority, certifier, ex, bank, m41, signers

def next_epoch(authority, ex, prev_manifest, epoch, certifier_pub,
               payee_allow=None, policy="P19", validator="V5"):
    body = make_body("PAY-GW-2", epoch, prev_manifest["acd"],
                     policy_digest=policy, validator_digest=validator,
                     certifier_pub=certifier_pub, executor_scope="PAY-GW-2",
                     executor_pub=ex.key.pub, target_pub=ex.target.pub,
                     payee_allow=payee_allow or ["V-8841"], tx_limit=50_000)
    return authority.issue(body)

def main():
    root = tempfile.mkdtemp(prefix="ebae_")

    # ---------------- happy path -------------------------------------
    tmp = os.path.join(root, "hp"); os.makedirs(tmp)
    authority, certifier, ex, bank, m41, signers = fresh_world(tmp)
    intent = make_intent(m41["acd"])
    cert = certifier.certify(intent, m41)
    op = ex.verify_and_reserve(intent, cert)
    rcpt = ex.send(op)
    check("happy_path", "$40k certified transfer",
          rcpt["disposition"] == "COMPLETED" and len(bank.transfers) == 1
          and bank.balances["OPS-1"] == 60_000,
          f"disposition={rcpt['disposition']}, transfers={len(bank.transfers)}")

    # ---------------- certificate replay -----------------------------
    ok, d = expect_reject(lambda: ex.verify_and_reserve(intent, cert),
                          "certificate_already_consumed")
    check("certificate_replay", "resubmit consumed one-use certificate", ok, d)
    check("replay_no_effect", "no second transfer occurred",
          len(bank.transfers) == 1)

    # ---------------- intent substitution ----------------------------
    intent2 = make_intent(m41["acd"], amount=45_000)
    cert2 = certifier.certify(intent2, m41)
    tampered = copy.deepcopy(intent2); tampered["parameters"]["amount"] = 49_999
    ok, d = expect_reject(lambda: ex.verify_and_reserve(tampered, cert2),
                          "intent_digest_mismatch")
    check("intent_substitution", "amount changed after certification", ok, d)

    # ---------------- quorum forgery ----------------------------------
    body_bad = make_body("PAY-GW-2", 42, m41["acd"], policy_digest="EVIL",
                         validator_digest="V5", certifier_pub=certifier.key.pub,
                         executor_scope="PAY-GW-2", executor_pub=ex.key.pub,
                         target_pub=bank.pub, payee_allow=["V-9999"],
                         tx_limit=10**9)
    one_sig = authority.issue(body_bad, sign_with=signers[:1])
    ok, d = expect_reject(lambda: ex.stage_manifest(one_sig), "quorum_not_met")
    check("quorum_forgery", "manifest with 1-of-3 signatures", ok, d)

    # ---------------- context splice (cross-epoch mix) ----------------
    # Certify under epoch 41 policy, then activate epoch 42 (new policy),
    # then try to execute the old-closure certificate.
    intent3 = make_intent(m41["acd"], amount=30_000)
    cert3 = certifier.certify(intent3, m41)          # bound to ACD_41
    m42 = next_epoch(authority, ex, m41, 42, certifier.key.pub)
    ex.activate_manifest(ex.stage_manifest(m42))      # no open reservations
    ok, d = expect_reject(lambda: ex.verify_and_reserve(intent3, cert3),
                          "acd_mismatch")
    check("context_splice", "old-policy certificate under new active ACD", ok, d)

    # ---------------- epoch-number collision --------------------------
    # Same epoch_id=43, two different bodies. Second must fail predecessor/ACD.
    m43a = next_epoch(authority, ex, m42, 43, certifier.key.pub, policy="P20")
    body43b = make_body("PAY-GW-2", 43, m42["acd"], policy_digest="P20-forged",
                        validator_digest="V5", certifier_pub=certifier.key.pub,
                        executor_scope="PAY-GW-2", executor_pub=ex.key.pub,
                        target_pub=bank.pub, payee_allow=["V-8841"],
                        tx_limit=50_000)
    m43b = authority.issue(body43b)
    ex.activate_manifest(ex.stage_manifest(m43a))
    ok, d = expect_reject(lambda: ex.stage_manifest(m43b),
                          "predecessor_mismatch")
    same_num_diff_acd = (m43a["acd"] != m43b["acd"])
    check("epoch_number_collision", "same epoch number, different body",
          ok and same_num_diff_acd, d + f"; distinct ACDs={same_num_diff_acd}")

    # ---------------- concurrent replay (race one certificate) --------
    intent4 = make_intent(m43a["acd"], amount=10_000)
    cert4 = certifier.certify(intent4, m43a)
    wins, losses = [], []
    def racer():
        try: wins.append(ex.verify_and_reserve(intent4, cert4))
        except Reject: losses.append(1)
    th = [threading.Thread(target=racer) for _ in range(16)]
    [t.start() for t in th]; [t.join() for t in th]
    check("concurrent_replay", "16 threads race one certificate",
          len(wins) == 1 and len(losses) == 15,
          f"reservations={len(wins)}, rejections={len(losses)}")
    ex.send(wins[0])   # drain so later transitions can be orderly

    # ---------------- TOCTOU drift ------------------------------------
    intent5 = make_intent(m43a["acd"], amount=5_000, vendor_version=18)
    cert5 = certifier.certify(intent5, m43a)
    op5 = ex.verify_and_reserve(intent5, cert5)
    bank.vendor_record_version = 19                  # drift after certification
    before = len(bank.transfers)
    r5 = ex.send(op5)
    check("toctou_drift", "vendor record changes before commit",
          r5["disposition"] == "ABORTED" and len(bank.transfers) == before,
          f"disposition={r5['disposition']}, no funds moved")
    bank.vendor_record_version = 18

    # ---------------- crash after effect (lost response) --------------
    intent6 = make_intent(m43a["acd"], amount=7_000)
    cert6 = certifier.certify(intent6, m43a)
    op6 = ex.verify_and_reserve(intent6, cert6)
    ex.send(op6, crash_after_send=True)              # bank commits, response lost
    before = len(bank.transfers)
    r6 = ex.recover(op6)                             # query same operation_id
    check("crash_after_effect", "response lost after bank commit",
          r6["disposition"] == "COMPLETED" and len(bank.transfers) == before
          and r6["recovery"],
          f"recovered disposition={r6['disposition']}, duplicates=0")

    # ---------------- crash before invoke -----------------------------
    intent7 = make_intent(m43a["acd"], amount=3_000)
    cert7 = certifier.certify(intent7, m43a)
    op7 = ex.verify_and_reserve(intent7, cert7)      # PREPARED, then "crash"
    r7 = ex.recover(op7)
    check("crash_before_invoke", "crash between reserve and send",
          r7["disposition"] == "ABORTED", f"disposition={r7['disposition']}")

    # ---------------- unknown outcome ----------------------------------
    intent8 = make_intent(m43a["acd"], amount=2_000)
    cert8 = certifier.certify(intent8, m43a)
    op8 = ex.verify_and_reserve(intent8, cert8)
    bank.offline = True
    try: ex.send(op8)
    except ConnectionError: pass
    r8 = ex.recover(op8)                              # target cannot answer
    replay_blocked, _ = expect_reject(
        lambda: ex.verify_and_reserve(intent8, cert8), "consumed")
    check("unknown_outcome", "target permanently unavailable after SENT",
          r8["disposition"] == "UNKNOWN" and replay_blocked,
          "UNKNOWN durable; no silent re-issue; certificate stays consumed")
    bank.offline = False

    # ---------------- conflicting retry --------------------------------
    forged = {"operation_id": op6, "target_id": "BANK-API",
              "payee": "V-EVIL", "amount": 1,
              "from_account": "OPS-1", "conditions": {}}
    resp = bank.invoke(forged, ex._executor_proof("invoke", forged))
    check("conflicting_retry", "reuse operation_id with different request",
          resp["status"] == "REJECTED_DIGEST_CONFLICT", resp["status"])

    # ---------------- bypass attempt ------------------------------------
    bypass = {"operation_id": "X", "target_id": "BANK-API",
              "payee": "V-EVIL", "amount": 999,
              "from_account": "OPS-1", "conditions": {}}
    resp = bank.invoke(bypass, None)
    check("bypass_attempt", "planner calls target directly",
          resp["status"] == "DENIED", resp["status"])

    # ---------------- emergency transition + orphan recovery ------------
    intent9 = make_intent(m43a["acd"], amount=1_500)
    cert9 = certifier.certify(intent9, m43a)
    op9 = ex.verify_and_reserve(intent9, cert9)       # open PREPARED reservation
    m44 = next_epoch(authority, ex, m43a, 44, certifier.key.pub, policy="P21")
    acd44 = ex.stage_manifest(m44)
    ok_block, d1 = expect_reject(lambda: ex.activate_manifest(acd44),
                                 "orderly_activation_blocked")
    ex.activate_manifest(acd44, emergency=True)       # compromise response
    orphan_send_blocked, _ = expect_reject(lambda: ex.send(op9),
                                           "reservation_orphaned")
    r9 = ex.recover(op9)                              # recovery permitted
    check("emergency_transition", "emergency activation with open reservation",
          ok_block and orphan_send_blocked and r9["disposition"] == "ABORTED",
          f"orderly blocked; orphan send blocked; orphan closed {r9['disposition']}")

    # ---------------- snapshot rollback ---------------------------------
    tmp2 = os.path.join(root, "rb"); os.makedirs(tmp2)
    authority2, certifier2, ex2, bank2, n41, _ = fresh_world(tmp2)
    snapshot = os.path.join(tmp2, "snap.db")
    shutil.copy(os.path.join(tmp2, "state.db"), snapshot)     # attacker snapshot
    i = make_intent(n41["acd"], amount=9_000)
    cc = certifier2.certify(i, n41)
    ex2.send(ex2.verify_and_reserve(i, cc))                   # advances anchor
    shutil.copy(snapshot, os.path.join(tmp2, "state.db"))     # restore old disk
    ex3 = ProtectedExecutor(os.path.join(tmp2, "state.db"),
                            ex2.anchor, authority2.trust_root,
                            ex2.key, "PAY-GW-2")
    ex3.target = bank2
    ok, d = expect_reject(ex3._startup_rollback_check, "rollback_detected")
    check("snapshot_rollback", "restore pre-consumption database snapshot",
          ok and ex3.safe_mode, d + f"; safe_mode={ex3.safe_mode}")

    # ==================================================================
    # v0.2 remediation regressions: one named test per audit finding.

    # ---------------- active manifest expiry ---------------------------
    tmp3 = os.path.join(root, "active_expiry"); os.makedirs(tmp3)
    a3, c3, e3, b3, n3, _ = fresh_world(tmp3)
    i3 = make_intent(n3["acd"], amount=1_001)
    cc3 = c3.certify(i3, n3)
    op3 = e3.verify_and_reserve(i3, cc3)
    i3b = make_intent(n3["acd"], amount=1_002)
    cc3b = c3.certify(i3b, n3)
    real_time = E.time.time
    E.time.time = lambda: n3["body"]["expires_at"] + 1
    try:
        cert_blocked, cert_detail = expect_reject(
            lambda: c3.certify(i3, n3), "manifest_expired")
        reserve_blocked, reserve_detail = expect_reject(
            lambda: e3.verify_and_reserve(i3b, cc3b),
            "manifest_expired")
        send_blocked, send_detail = expect_reject(
            lambda: e3.send(op3), "manifest_expired")
    finally:
        E.time.time = real_time
    phase3 = [r[1] for r in e3.dump_reservations() if r[0] == op3][0]
    check("active_manifest_expiry",
          "clock advances past active manifest before certification/release",
          cert_blocked and reserve_blocked and send_blocked
          and phase3 == "PREPARED"
          and len(b3.transfers) == 0,
          f"{cert_detail}; {reserve_detail}; {send_detail}; phase={phase3}")

    # ---------------- staged manifest expiry ---------------------------
    tmp4 = os.path.join(root, "staged_expiry"); os.makedirs(tmp4)
    a4, c4, e4, b4, n4, _ = fresh_world(tmp4)
    n42 = next_epoch(a4, e4, n4, 42, c4.key.pub)
    acd42 = e4.stage_manifest(n42)
    real_time = E.time.time
    E.time.time = lambda: n42["body"]["expires_at"] + 1
    try:
        expired_blocked, expired_detail = expect_reject(
            lambda: e4.activate_manifest(acd42), "manifest_expired")
    finally:
        E.time.time = real_time
    check("staged_manifest_expiry",
          "staged envelope expires before activation",
          expired_blocked and e4._manifest["acd"] == n4["acd"],
          expired_detail + "; previous epoch remains active")

    # ---------------- activation revalidates staged data ----------------
    tmp5 = os.path.join(root, "staged_tamper"); os.makedirs(tmp5)
    a5, c5, e5, b5, n5, _ = fresh_world(tmp5)
    n43 = next_epoch(a5, e5, n5, 43, c5.key.pub)
    acd43 = e5.stage_manifest(n43)
    staged_tamper = copy.deepcopy(n43)
    staged_tamper["body"]["action_classes"]["vendor_payment"]["tx_limit"] = 10**9
    conn5 = e5._conn()
    conn5.execute("UPDATE staged SET envelope=? WHERE acd=?",
                  (json.dumps(staged_tamper), acd43))
    conn5.close()
    tamper_blocked, tamper_detail = expect_reject(
        lambda: e5.activate_manifest(acd43), "acd_recompute_mismatch")
    floor_dir = os.path.join(tmp5, "initial_floor"); os.makedirs(floor_dir)
    floor_signers = [Signer(f"floor-auth-{i}") for i in range(3)]
    floor_authority = ManifestAuthority(floor_signers, quorum=2)
    floor_cert_key = Signer("floor-certifier")
    floor_exec_key = Signer("floor-executor")
    floor_bank = MockBank(os.path.join(floor_dir, "bank.db"),
                          floor_exec_key.pub)
    floor_ex = ProtectedExecutor(
        os.path.join(floor_dir, "state.db"),
        MonotonicAnchor(os.path.join(floor_dir, "anchor.nv")),
        floor_authority.trust_root, floor_exec_key, "PAY-GW-2")
    floor_ex.target = floor_bank
    floor_body = make_body(
        "PAY-GW-2", 1, None, policy_digest="P-floor",
        validator_digest="V-floor", certifier_pub=floor_cert_key.pub,
        executor_scope="PAY-GW-2", executor_pub=floor_exec_key.pub,
        target_pub=floor_bank.pub, payee_allow=["V-8841"],
        tx_limit=50_000, state_floor=999)
    floor_env = floor_authority.issue(floor_body)
    floor_conn = floor_ex._conn()
    floor_conn.execute("INSERT INTO staged(acd,envelope) VALUES(?,?)",
                       (floor_env["acd"], json.dumps(floor_env)))
    floor_conn.close()
    floor_blocked, floor_detail = expect_reject(
        lambda: floor_ex.activate_manifest(floor_env["acd"]),
        "state_floor_unsatisfied")
    missing_target_body = make_body(
        "PAY-GW-2", 44, n5["acd"], policy_digest="P-missing-target",
        validator_digest="V5", certifier_pub=c5.key.pub,
        executor_scope="PAY-GW-2", executor_pub=e5.key.pub,
        target_pub=b5.pub, payee_allow=["V-8841"], tx_limit=50_000)
    missing_target_body["target_operation_profiles"].pop("BANK-API")
    missing_target_body["target_operation_profiles"]["OTHER-TARGET"] = {
        "profile": "B_idempotent_conditional",
        "target_pub": Signer("unattached-target").pub}
    missing_target_env = a5.issue(missing_target_body)
    target_conn = e5._conn()
    target_conn.execute("INSERT INTO staged(acd,envelope) VALUES(?,?)",
                        (missing_target_env["acd"],
                         json.dumps(missing_target_env)))
    target_conn.close()
    missing_target_blocked, missing_target_detail = expect_reject(
        lambda: e5.activate_manifest(missing_target_env["acd"]),
        "target_identity_mismatch")
    check("activation_revalidates_staged_data",
          "mutate a staged envelope after initial validation",
          tamper_blocked and floor_blocked and missing_target_blocked
          and e5._manifest["acd"] == n5["acd"],
          tamper_detail + f"; initial floor: {floor_detail}; "
          f"attached target: {missing_target_detail}")

    # ---------------- restart restores active state --------------------
    tmp6 = os.path.join(root, "restart"); os.makedirs(tmp6)
    a6, c6, e6, b6, n6, _ = fresh_world(tmp6)
    i6a = make_intent(n6["acd"], amount=1_100)
    r6a = e6.send(e6.verify_and_reserve(i6a, c6.certify(i6a, n6)))
    conn6 = e6._conn()
    committed_sequence = e6._state(conn6)["continuity_seq"]
    conn6.close()
    lagging_anchor = MonotonicAnchor(os.path.join(tmp6, "lagging-anchor.nv"))
    e6r = ProtectedExecutor(os.path.join(tmp6, "state.db"), lagging_anchor,
                            a6.trust_root, e6.key, "PAY-GW-2")
    e6r.target = b6
    restored_before = len(e6r.receipts)
    i6b = make_intent(n6["acd"], amount=1_200)
    r6b = e6r.send(e6r.verify_and_reserve(i6b, c6.certify(i6b, n6)))
    check("restart_restores_active_state",
          "restart executor after a closed operation",
          e6r._manifest["acd"] == n6["acd"] and restored_before == 1
          and r6a["disposition"] == r6b["disposition"] == "COMPLETED"
          and lagging_anchor.read() >= committed_sequence
          and e6r.receipt_count() == 2 and len(b6.transfers) == 2,
          f"restored_receipts={restored_before}, durable_receipts="
          f"{e6r.receipt_count()}, caught_up_anchor={lagging_anchor.read()}")

    # ---------------- SENT but target proves ABSENT --------------------
    tmp7 = os.path.join(root, "sent_absent"); os.makedirs(tmp7)
    a7, c7, e7, b7, n7, _ = fresh_world(tmp7)
    i7 = make_intent(n7["acd"], amount=1_300)
    op7a = e7.verify_and_reserve(i7, c7.certify(i7, n7))
    b7.offline = True
    try:
        e7.send(op7a)
    except ConnectionError:
        pass
    b7.offline = False
    r7a = e7.recover(op7a)
    check("sent_but_not_received",
          "SENT locally; target returns signed authoritative ABSENT",
          r7a["disposition"] == "ABORTED" and r7a["recovery"]
          and not e7.safe_mode and len(b7.transfers) == 0,
          f"disposition={r7a['disposition']}, safe_mode={e7.safe_mode}")

    # ---------------- SENT transition rollback ------------------------
    tmp8 = os.path.join(root, "sent_rollback"); os.makedirs(tmp8)
    a8, c8, e8, b8, n8, _ = fresh_world(tmp8)
    i8 = make_intent(n8["acd"], amount=1_400)
    op8a = e8.verify_and_reserve(i8, c8.certify(i8, n8))
    snapshot8 = os.path.join(tmp8, "prepared.snapshot.db")
    sqlite_snapshot(os.path.join(tmp8, "state.db"), snapshot8)
    b8.offline = True
    try:
        e8.send(op8a)
    except ConnectionError:
        pass
    sent_anchor = e8.anchor.read()
    sqlite_snapshot(snapshot8, os.path.join(tmp8, "state.db"))
    e8r = ProtectedExecutor(os.path.join(tmp8, "state.db"), e8.anchor,
                            a8.trust_root, e8.key, "PAY-GW-2")
    e8r.target = b8
    rollback_blocked, rollback_detail = expect_reject(
        e8r._startup_rollback_check, "rollback_detected")
    check("sent_transition_rollback",
          "restore PREPARED snapshot after durable SENT transition",
          rollback_blocked and e8r.safe_mode
          and e8r.anchor.read() == sent_anchor,
          rollback_detail + f"; anchor={sent_anchor}")

    # ---------------- malformed/negative amounts ----------------------
    tmp9 = os.path.join(root, "amounts"); os.makedirs(tmp9)
    a9, c9, e9, b9, n9, _ = fresh_world(tmp9)
    amount_rejections = []
    for bad_amount in (-1, 0, True, 1.5):
        bad_intent = make_intent(n9["acd"], amount=bad_amount)
        rejected, _detail = expect_reject(
            lambda bad_intent=bad_intent: c9.certify(bad_intent, n9),
            "invalid_amount")
        amount_rejections.append(rejected)
    direct_bad = {"operation_id": "invalid-negative",
                  "target_id": "BANK-API", "payee": "V-8841",
                  "amount": -10, "from_account": "OPS-1",
                  "conditions": {"vendor_record_version": 18}}
    balance_before = b9.balances["OPS-1"]
    bad_response = b9.invoke(
        direct_bad, e9._executor_proof("invoke", direct_bad))
    check("invalid_amounts",
          "negative, zero, Boolean, float, and direct negative amount",
          all(amount_rejections) and bad_response["status"] == "ABORTED"
          and bad_response.get("reason") == "invalid_amount"
          and b9.balances["OPS-1"] == balance_before
          and len(b9.transfers) == 0,
          f"certifier_rejections={sum(amount_rejections)}/4; "
          f"target_status={bad_response['status']}")

    # ---------------- executor proof of possession --------------------
    tmp10 = os.path.join(root, "executor_pop"); os.makedirs(tmp10)
    a10, c10, e10, b10, n10, _ = fresh_world(tmp10)
    pop_request = {"operation_id": "forged-executor",
                   "target_id": "BANK-API", "payee": "V-8841",
                   "amount": 10, "from_account": "OPS-1",
                   "conditions": {"vendor_record_version": 18}}
    forged_proof = e10._executor_proof("invoke", pop_request)
    attacker = Signer("attacker")
    forged_proof["signature"] = attacker.sign(
        E.EXECUTOR_PROOF_DOMAIN, forged_proof["core"])
    pop_response = b10.invoke(pop_request, forged_proof)
    other_target = Signer("other-target")
    multi_body = make_body(
        "PAY-GW-2", 42, n10["acd"], policy_digest="P19",
        validator_digest="V5", certifier_pub=c10.key.pub,
        executor_scope="PAY-GW-2", executor_pub=e10.key.pub,
        target_pub=b10.pub, payee_allow=["V-8841"], tx_limit=50_000)
    multi_body["target_operation_profiles"]["OTHER-TARGET"] = {
        "profile": "B_idempotent_conditional",
        "target_pub": other_target.pub}
    multi_manifest = a10.issue(multi_body)
    e10.activate_manifest(e10.stage_manifest(multi_manifest))
    cross_intent = make_intent(multi_manifest["acd"], amount=11)
    cross_intent["target_id"] = "OTHER-TARGET"
    cross_cert = c10.certify(cross_intent, multi_manifest)
    cross_blocked, cross_detail = expect_reject(
        lambda: e10.verify_and_reserve(cross_intent, cross_cert),
        "target_identity_mismatch")
    cross_request = {"operation_id": "cross-target",
                     "target_id": "OTHER-TARGET", "payee": "V-8841",
                     "amount": 11, "from_account": "OPS-1",
                     "conditions": {"vendor_record_version": 18}}
    cross_response = b10.invoke(
        cross_request, e10._executor_proof("invoke", cross_request))
    check("executor_proof_of_possession",
          "forged executor proof and cross-target routing confusion",
          pop_response["status"] == "DENIED"
          and cross_blocked and cross_response["status"] == "DENIED"
          and len(b10.transfers) == 0,
          f"forged={pop_response['status']}; {cross_detail}; "
          f"cross_target={cross_response['status']}")

    # ---------------- forged target response + persistent safe mode ----
    tmp11 = os.path.join(root, "forged_response"); os.makedirs(tmp11)
    a11, c11, e11, b11, n11, _ = fresh_world(tmp11)
    i11 = make_intent(n11["acd"], amount=1_500, vendor_version=999)
    op11 = e11.verify_and_reserve(i11, c11.certify(i11, n11))
    anchor_before_forge = e11.anchor.read()
    b11.forge_next_response = True
    forged_blocked, forged_detail = expect_reject(
        lambda: e11.send(op11), "forged_target_response")
    e11r = ProtectedExecutor(os.path.join(tmp11, "state.db"), e11.anchor,
                             a11.trust_root, e11.key, "PAY-GW-2")
    e11r.target = b11
    check("forged_target_response",
          "target response carries an invalid signature",
          forged_blocked and e11.safe_mode and e11r.safe_mode
          and e11r.safe_reason == "forged_target_response"
          and e11.anchor.read() > anchor_before_forge
          and len(b11.transfers) == 0,
          forged_detail + f"; restart_safe_mode={e11r.safe_mode}; "
          f"anchor={e11.anchor.read()}")

    # ---------------- persistent target idempotency -------------------
    tmp12 = os.path.join(root, "target_restart"); os.makedirs(tmp12)
    a12, c12, e12, b12, n12, _ = fresh_world(tmp12)
    i12 = make_intent(n12["acd"], amount=1_600)
    op12 = e12.verify_and_reserve(i12, c12.certify(i12, n12))
    e12.send(op12, crash_after_send=True)
    b12r = MockBank(os.path.join(tmp12, "bank.db"), e12.key.pub, key=b12.key)
    e12.target = b12r
    recovered12 = e12.recover(op12)
    conn12 = e12._conn()
    request12 = json.loads(conn12.execute(
        "SELECT request FROM reservations WHERE operation_id=?",
        (op12,)).fetchone()[0])
    conn12.close()
    repeated12 = b12r.invoke(
        request12, e12._executor_proof("invoke", request12))
    check("persistent_target_idempotency",
          "restart target after effect, then query and retry same operation",
          recovered12["disposition"] == "COMPLETED"
          and repeated12["status"] == "COMPLETED"
          and len(b12r.transfers) == 1,
          f"recovered={recovered12['disposition']}, "
          f"durable_transfers={len(b12r.transfers)}")

    # ---------------- idempotent concurrent close ---------------------
    tmp13 = os.path.join(root, "concurrent_close"); os.makedirs(tmp13)
    a13, c13, e13, b13, n13, _ = fresh_world(tmp13)
    i13 = make_intent(n13["acd"], amount=1_700)
    op13 = e13.verify_and_reserve(i13, c13.certify(i13, n13))
    e13.send(op13, crash_after_send=True)
    closes, close_errors = [], []
    def closer():
        try:
            closes.append(e13.recover(op13))
        except BaseException as exc:
            close_errors.append(str(exc))
    close_threads = [threading.Thread(target=closer) for _ in range(12)]
    [thread.start() for thread in close_threads]
    [thread.join() for thread in close_threads]
    distinct_receipts = {json.dumps(r, sort_keys=True) for r in closes}
    check("idempotent_concurrent_close",
          "12 recovery threads race to close one SENT operation",
          len(closes) == 12 and not close_errors
          and len(distinct_receipts) == 1
          and e13.receipt_count() == 1 and len(e13.receipts) == 1,
          f"returns={len(closes)}, stored_receipts={e13.receipt_count()}, "
          f"errors={len(close_errors)}")

    # ---------------- nonce uniqueness across certificates ------------
    tmp14 = os.path.join(root, "nonce_unique"); os.makedirs(tmp14)
    a14, c14, e14, b14, n14, _ = fresh_world(tmp14)
    i14 = make_intent(n14["acd"], amount=1_800)
    cert14a = c14.certify(i14, n14)
    e14.verify_and_reserve(i14, cert14a)
    cert14b = c14.certify(i14, n14)
    cert14b["one_time_nonce"] = cert14a["one_time_nonce"]
    cert14b.pop("certifier_signature")
    cert14b["certifier_signature"] = c14.key.sign(E.CERT_DOMAIN, cert14b)
    nonce_blocked, nonce_detail = expect_reject(
        lambda: e14.verify_and_reserve(i14, cert14b),
        "nonce_already_consumed")
    check("nonce_unique_across_certificates",
          "new certificate ID reuses an already consumed nonce",
          nonce_blocked and len(e14.dump_reservations()) == 1,
          nonce_detail)

    # ---------------- ledger accounting ----------------------------------
    authorized = {"happy_path": 1, "concurrent": 1, "crash_after": 1}
    check("effect_accounting", "every realized transfer maps to a receipt",
          len(bank.transfers) == 3 and
          all(any(r["operation_id"] == t["op"] and r["disposition"] == "COMPLETED"
                  for r in ex.receipts) for t in bank.transfers),
          f"transfers={len(bank.transfers)}, receipts={len(ex.receipts)}")

    # ---------------- summary -------------------------------------------
    passed = sum(1 for *_ , ok, _d in [(a,b,c,d) for a,b,c,d in RESULTS] if ok)
    print("\n" + "=" * 74)
    print(f"RESULT: {passed}/{len(RESULTS)} tests passed · "
          f"unauthorized external effects: 0 required")
    unauthorized = len(bank.transfers) - 3
    print(f"realized transfers in adversarial world: {len(bank.transfers)} "
          f"(all 3 authorized) · unauthorized: {unauthorized}")
    if passed != len(RESULTS) or unauthorized != 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
