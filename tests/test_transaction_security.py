from guardrails.transaction_security import evaluate_transaction


def test_unauthenticated_transaction_requires_authorization():
    result = evaluate_transaction(
        request_id="r1", amount="1000", currency="INR",
        beneficiary_id="b1", session_valid=True, authenticated=False,
    )
    assert result["verdict"] == "REQUIRE_AUTHORIZATION"
    assert result["rule_ids"] == ["AUTH-TRANSACTION-001"]


def test_expired_session_requires_review():
    result = evaluate_transaction(
        request_id="r1", amount="1000", currency="INR",
        beneficiary_id="b1", session_valid=False, authenticated=True,
    )
    assert result["verdict"] == "REVIEW"
    assert result["rule_ids"] == ["SESSION-EXPIRED-001"]


def test_changed_amount_invalidates_previous_approval():
    result = evaluate_transaction(
        request_id="r1", amount="10000", currency="INR",
        beneficiary_id="b1", session_valid=True, authenticated=True,
        approved_amount="1000", approved_currency="INR",
        approved_beneficiary_id="b1",
    )
    assert result["verdict"] == "REQUIRE_AUTHORIZATION"
    assert result["rule_ids"] == ["TXN-APPROVAL-BINDING-001"]


def test_changed_beneficiary_invalidates_previous_approval():
    result = evaluate_transaction(
        request_id="r1", amount="1000", currency="INR",
        beneficiary_id="b2", session_valid=True, authenticated=True,
        approved_amount="1000", approved_currency="INR",
        approved_beneficiary_id="b1",
    )
    assert result["verdict"] == "REQUIRE_AUTHORIZATION"


def test_duplicate_request_is_blocked():
    result = evaluate_transaction(
        request_id="r1", amount="1000", currency="INR",
        beneficiary_id="b1", session_valid=True, authenticated=True,
        previously_seen_request_ids={"r1"},
    )
    assert result["verdict"] == "BLOCK"
    assert result["rule_ids"] == ["TXN-IDEMPOTENCY-001"]


def test_new_beneficiary_requires_step_up():
    result = evaluate_transaction(
        request_id="r1", amount="1000", currency="INR",
        beneficiary_id="b1", session_valid=True, authenticated=True,
        is_new_beneficiary=True,
    )
    assert result["verdict"] == "REQUIRE_AUTHORIZATION"
    assert result["rule_ids"] == ["BENEFICIARY-STEPUP-001"]


def test_limits_are_enforced():
    result = evaluate_transaction(
        request_id="r1", amount="5000", currency="INR",
        beneficiary_id="b1", session_valid=True, authenticated=True,
        per_transaction_limit="3000",
    )
    assert result["verdict"] == "REVIEW"
    assert result["rule_ids"] == ["TXN-LIMIT-001"]


def test_valid_transaction_policy_passes_without_execution():
    result = evaluate_transaction(
        request_id="r1", amount="1000", currency="INR",
        beneficiary_id="b1", session_valid=True, authenticated=True,
        approved_amount="1000", approved_currency="INR",
        approved_beneficiary_id="b1",
    )
    assert result["verdict"] == "ALLOW"
    assert result["transaction_executed"] is False
