"""Structured, deterministic transaction controls for SecureFin Gateway.

This module evaluates transaction metadata only. It does not connect to a bank,
move funds, authenticate a real customer, or execute a payment.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any


def _money(value: Any, field: str) -> Decimal:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"{field} must be a valid decimal amount.")
    if not amount.is_finite() or amount < 0:
        raise ValueError(f"{field} must be a finite non-negative amount.")
    return amount


def _decision(verdict: str, rule_id: str, reason: str) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "rule_ids": [rule_id],
        "message": reason,
        "transaction_executed": False,
    }


def evaluate_transaction(
    *,
    request_id: str,
    amount: Any,
    currency: str,
    beneficiary_id: str,
    session_valid: bool,
    authenticated: bool,
    step_up_verified: bool = False,
    approved_amount: Any | None = None,
    approved_currency: str | None = None,
    approved_beneficiary_id: str | None = None,
    previously_seen_request_ids: set[str] | None = None,
    is_new_beneficiary: bool = False,
    per_transaction_limit: Any = "100000",
    daily_total: Any = "0",
    daily_limit: Any = "200000",
    step_up_threshold: Any = "25000",
) -> dict[str, Any]:
    """Evaluate a proposed payment against structured approval and risk state.

    All amounts are interpreted in the supplied currency. The function is a
    policy simulation; the caller must enforce the returned decision in the
    actual payment service before any transaction can execute.
    """
    if not isinstance(request_id, str) or not request_id.strip():
        return _decision("BLOCK", "TXN-REQ-001", "A non-empty request ID is required.")
    if not isinstance(beneficiary_id, str) or not beneficiary_id.strip():
        return _decision("REVIEW", "TXN-DATA-001", "A beneficiary is required before payment review.")
    if not isinstance(currency, str) or len(currency.strip()) != 3 or not currency.isalpha():
        return _decision("BLOCK", "TXN-CURRENCY-001", "Currency must be a three-letter ISO-style code.")

    try:
        tx_amount = _money(amount, "amount")
        tx_limit = _money(per_transaction_limit, "per_transaction_limit")
        current_daily = _money(daily_total, "daily_total")
        day_limit = _money(daily_limit, "daily_limit")
        step_threshold = _money(step_up_threshold, "step_up_threshold")
        approved = _money(approved_amount, "approved_amount") if approved_amount is not None else None
    except ValueError as exc:
        return _decision("BLOCK", "TXN-AMOUNT-001", str(exc))

    if tx_amount <= 0:
        return _decision("BLOCK", "TXN-AMOUNT-001", "Transaction amount must be greater than zero.")

    seen = previously_seen_request_ids or set()
    if request_id in seen:
        return _decision("BLOCK", "TXN-IDEMPOTENCY-001", "Duplicate request ID detected; duplicate processing is not permitted.")

    if not session_valid:
        return _decision("REVIEW", "SESSION-EXPIRED-001", "Session is expired. Re-authentication is required.")

    if not authenticated:
        return _decision("REQUIRE_AUTHORIZATION", "AUTH-TRANSACTION-001", "A verified customer session is required before transaction processing.")

    if tx_amount > tx_limit or current_daily + tx_amount > day_limit:
        return _decision("REVIEW", "TXN-LIMIT-001", "Configured transaction or daily limit would be exceeded; manual review is required.")

    # Approval binding: a prior approval is valid only for the exact amount,
    # currency and beneficiary that were approved.
    if approved is not None:
        if (
            tx_amount != approved
            or (approved_currency or "").strip().upper() != currency.strip().upper()
            or (approved_beneficiary_id or "").strip().casefold() != beneficiary_id.strip().casefold()
        ):
            return _decision("REQUIRE_AUTHORIZATION", "TXN-APPROVAL-BINDING-001", "Amount, currency or beneficiary differs from the approved transaction. Obtain fresh approval.")

    if is_new_beneficiary and not step_up_verified:
        return _decision("REQUIRE_AUTHORIZATION", "BENEFICIARY-STEPUP-001", "A new beneficiary requires step-up verification.")

    if tx_amount >= step_threshold and not step_up_verified:
        return _decision("REQUIRE_AUTHORIZATION", "TXN-STEPUP-001", "This transaction meets the configured step-up threshold.")

    return _decision("ALLOW", "TXN-POLICY-PASS-001", "Structured transaction checks passed. This is a policy approval only; the payment service must still enforce execution controls.")
