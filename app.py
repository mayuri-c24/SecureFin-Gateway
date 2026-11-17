
import streamlit as st
from datetime import datetime

from guardrails.policy_engine import evaluate_message
from guardrails.output_guardrail import validate_output
from guardrails.transaction_security import evaluate_transaction
from guardrails.audit_logger import log_event, read_events, verify_chain


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SecureFin Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# --------------------------------------------------
# PROFESSIONAL BANKING THEME
# --------------------------------------------------

st.markdown("""
<style>
    .stApp {
        background-color: #F4F7FB;
    }

    [data-testid="stSidebar"] {
        background-color: #102747;
    }

    [data-testid="stSidebar"] * {
        color: white !important;
    }

    .main-title {
        font-size: 32px;
        font-weight: 750;
        color: #102747;
        margin-bottom: 0;
    }

    .subtitle {
        color: #68788B;
        font-size: 14px;
        margin-bottom: 22px;
    }

    .info-card {
        background: white;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #E1E8F0;
        box-shadow: 0 2px 8px rgba(20, 40, 70, 0.04);
        min-height: 120px;
    }

    .metric-label {
        color: #66768A;
        font-size: 13px;
    }

    .metric-value {
        color: #102747;
        font-size: 27px;
        font-weight: 750;
    }

    .section-card {
        background: white;
        padding: 24px;
        border-radius: 12px;
        border: 1px solid #E1E8F0;
        margin-bottom: 18px;
    }

    .decision {
        padding: 15px;
        border-radius: 10px;
        font-size: 19px;
        font-weight: 750;
        text-align: center;
        margin: 12px 0;
    }

    .stButton > button {
        background-color: #1769AA;
        color: white;
        border-radius: 8px;
        border: none;
        min-height: 43px;
        font-weight: 650;
        width: 100%;
    }

    .stButton > button:hover {
        background-color: #105487;
        color: white;
        border: none;
    }

    h1, h2, h3 {
        color: #102747;
    }

    div[data-testid="stTextArea"] textarea {
        background-color: #FFFFFF;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# SESSION DATA
# Store metadata only, not customer message text.
# --------------------------------------------------

if "activity" not in st.session_state:
    st.session_state.activity = []

if "scan_count" not in st.session_state:
    st.session_state.scan_count = 0


def record_activity(decision_type, verdict, rule_ids):
    safe_rules = list(map(str, rule_ids)) if rule_ids else []
    st.session_state.activity.append({
        "time": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "type": decision_type,
        "verdict": str(verdict),
        "rules": ", ".join(safe_rules) if safe_rules else "No rule ID"
    })
    # Persist decision metadata only. Never pass the customer message or response.
    try:
        log_event(decision_type, str(verdict), safe_rules)
    except Exception:
        # UI remains usable if local audit storage is unavailable.
        pass


# --------------------------------------------------
# COMMON DISPLAY FUNCTION
# --------------------------------------------------

def show_decision(verdict, reason, rule_ids, details=None):
    verdict = str(verdict).upper()

    colors = {
        "ALLOW": ("#E5F5EC", "#18794E"),
        "REDACT": ("#E8F1FF", "#1769AA"),
        "BLOCK": ("#FCE8E8", "#B42318"),
        "ESCALATE": ("#FFF3DC", "#A15C00"),
        "REVIEW": ("#FFF3DC", "#A15C00"),
        "REQUIRE_AUTHORIZATION": ("#FFF3DC", "#A15C00"),
    }

    background, foreground = colors.get(
        verdict, ("#EDF0F5", "#344054")
    )

    st.markdown(
        f"""
        <div class="decision"
             style="background:{background}; color:{foreground};">
            DECISION: {verdict}
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("### Decision explanation")
    st.write(reason if reason else "No explanation was returned.")

    st.markdown("### Triggered policy rules")
    if rule_ids:
        for rule in rule_ids:
            st.code(str(rule))
    else:
        st.write("No rule ID returned.")

    if details is not None:
        st.markdown("### Detected information")
        st.json(details)


# --------------------------------------------------
# SIDEBAR NAVIGATION
# --------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ SecureFin")
    st.caption("BFSI Security Gateway")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Security Scanner",
            "Output Validator",
            "Policy Information",
            "Transaction Security Lab",
            "Session Activity",
            "Audit Trail"
        ]
    )

    st.divider()
    st.caption("DEMO ENVIRONMENT")
    st.success("Application interface active")
    st.caption("Rule-based processing")


# --------------------------------------------------
# PAGE 1: OVERVIEW
# --------------------------------------------------

if page == "Overview":

    st.markdown(
        '<div class="main-title">Security Dashboard</div>',
        unsafe_allow_html=True
    )
    st.markdown(
        '<div class="subtitle">Monitor deterministic BFSI security checks and policy decisions.</div>',
        unsafe_allow_html=True
    )

    total = st.session_state.scan_count

    allow_count = sum(
        1 for x in st.session_state.activity
        if x["verdict"].upper() == "ALLOW"
    )

    block_count = sum(
        1 for x in st.session_state.activity
        if x["verdict"].upper() == "BLOCK"
    )

    review_count = sum(
        1 for x in st.session_state.activity
        if x["verdict"].upper() in [
            "REVIEW", "ESCALATE", "REQUIRE_AUTHORIZATION"
        ]
    )

    c1, c2, c3, c4 = st.columns(4)

    metrics = [
        ("Messages checked", total),
        ("Allowed", allow_count),
        ("Blocked", block_count),
        ("Review / escalation", review_count)
    ]

    for col, (label, value) in zip(
        [c1, c2, c3, c4], metrics
    ):
        with col:
            st.markdown(
                f"""
                <div class="info-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    st.write("")
    st.markdown("### Gateway capabilities")

    a, b = st.columns(2)

    with a:
        st.markdown(
            """
            <div class="section-card">
                <h3>🔍 Input Security</h3>
                <p>Inspect customer messages for configured PII,
                risky instructions and sensitive actions.</p>
            </div>
            """,
            unsafe_allow_html=True
        )

    with b:
        st.markdown(
            """
            <div class="section-card">
                <h3>🛡️ Output Protection</h3>
                <p>Validate proposed chatbot responses for
                configured unsafe claims and sensitive information.</p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.info(
        "This prototype uses predefined Python rules and "
        "regular expressions. It does not call an external AI API."
    )


# --------------------------------------------------
# PAGE 2: SECURITY SCANNER
# --------------------------------------------------

elif page == "Security Scanner":

    st.markdown(
        '<div class="main-title">Security Scanner</div>',
        unsafe_allow_html=True
    )
    st.markdown(
        '<div class="subtitle">Analyze customer messages using the input policy engine.</div>',
        unsafe_allow_html=True
    )

    with st.container(border=True):

        st.markdown("### Enter customer message")

        message = st.text_area(
            "Message to analyze",
            height=180,
            placeholder=(
                "Example: My PAN is ABCDE1234F. "
                "Please check my account details."
            )
        )

        auth_level = st.selectbox(
            "Authentication context",
            [
                "unauthenticated",
                "authenticated"
            ]
        )

        if st.button("Analyze Message", key="scan_button"):

            if not message.strip():
                st.warning("Please enter a message first.")

            else:
                try:
                    with st.spinner("Applying security policies..."):

                        result = evaluate_message(
                            message,
                            auth_level=auth_level
                        )

                    st.session_state.scan_count += 1

                    verdict = result.get("verdict", "UNKNOWN")
                    reason = result.get("message", "")
                    rule_ids = result.get("rule_ids", [])
                    entities = result.get("entities", {})

                    record_activity(
                        "Input Scan",
                        verdict,
                        rule_ids
                    )

                    st.success("Analysis completed.")

                    show_decision(
                        verdict,
                        reason,
                        rule_ids,
                        entities
                    )

                except Exception as error:
                    st.error(
                        "The policy engine returned an error."
                    )
                    st.exception(error)


# --------------------------------------------------
# PAGE 3: OUTPUT VALIDATOR
# --------------------------------------------------

elif page == "Output Validator":

    st.markdown(
        '<div class="main-title">Output Validator</div>',
        unsafe_allow_html=True
    )
    st.markdown(
        '<div class="subtitle">Check a proposed chatbot response before it is displayed.</div>',
        unsafe_allow_html=True
    )

    with st.container(border=True):

        response = st.text_area(
            "Proposed chatbot response",
            height=180,
            placeholder=(
                "Enter a proposed banking chatbot response here..."
            )
        )

        if st.button("Validate Response"):

            if not response.strip():
                st.warning("Please enter a response.")

            else:
                try:
                    with st.spinner("Validating output..."):

                        result = validate_output(response)

                    verdict = result.get("verdict", "UNKNOWN")
                    reason = result.get("reason", "")
                    rule_ids = result.get("rule_ids", [])
                    safe_text = result.get("safe_text", "")

                    record_activity(
                        "Output Validation",
                        verdict,
                        rule_ids
                    )

                    st.session_state.scan_count += 1

                    st.success("Output validation completed.")

                    show_decision(
                        verdict,
                        reason,
                        rule_ids
                    )

                    st.markdown("### Validated response")

                    if safe_text:
                        st.text_area(
                            "Safe output",
                            value=str(safe_text),
                            height=120
                        )
                    else:
                        st.warning(
                            "The validator did not return safe_text."
                        )

                except Exception as error:
                    st.error(
                        "The output validator returned an error."
                    )
                    st.exception(error)


# --------------------------------------------------
# PAGE 4: POLICY INFORMATION
# --------------------------------------------------

elif page == "Policy Information":

    st.markdown(
        '<div class="main-title">Policy Information</div>',
        unsafe_allow_html=True
    )
    st.markdown(
        '<div class="subtitle">Overview of security policy categories implemented in the prototype.</div>',
        unsafe_allow_html=True
    )

    policies = [
        (
            "PII Protection",
            "Detect and protect supported identifiers such as PAN, "
            "Aadhaar, card and account-like numbers."
        ),
        (
            "Prompt Injection",
            "Identify configured attempts to override or disable "
            "the security policy."
        ),
        (
            "Credential Safety",
            "Check for configured OTP and credential-theft patterns."
        ),
        (
            "Financial Advice",
            "Apply configured checks for guaranteed-return claims."
        ),
        (
            "Fraud and Complaints",
            "Identify configured fraud and complaint signals for escalation."
        ),
        (
            "Sensitive Actions",
            "Check configured transfer, payment and account-change patterns."
        )
    ]

    for title, description in policies:
        with st.expander(title):
            st.write(description)

    st.warning(
        "This page describes policy categories. "
        "Refer to the actual policy_engine.py file for the "
        "complete active rule IDs and conditions."
    )



# --------------------------------------------------
# PAGE 5: STRUCTURED TRANSACTION SECURITY LAB
# --------------------------------------------------

elif page == "Transaction Security Lab":

    st.markdown(
        '<div class="main-title">Transaction Security Lab</div>',
        unsafe_allow_html=True
    )
    st.markdown(
        '<div class="subtitle">Evaluate transaction metadata, approval binding, duplicate requests and step-up controls. Simulation only — no payment is executed.</div>',
        unsafe_allow_html=True
    )

    with st.container(border=True):
        st.markdown("### Proposed transaction")
        c1, c2 = st.columns(2)
        with c1:
            request_id = st.text_input("Request ID", value="demo-request-001")
            amount = st.number_input("Amount", min_value=0.0, value=1000.0, step=100.0)
            currency = st.selectbox("Currency", ["INR", "USD", "EUR", "GBP"])
            beneficiary = st.text_input("Beneficiary ID", value="BENEFICIARY-A")
        with c2:
            session_valid = st.checkbox("Session is valid", value=True)
            authenticated = st.checkbox("Customer authenticated", value=False)
            step_up = st.checkbox("Step-up verification completed", value=False)
            new_beneficiary = st.checkbox("New beneficiary", value=False)

        st.markdown("### Previously approved transaction (optional)")
        has_approval = st.checkbox("Compare against an existing approval", value=True)
        if has_approval:
            ac1, ac2 = st.columns(2)
            with ac1:
                approved_amount = st.number_input("Approved amount", min_value=0.0, value=1000.0, step=100.0)
                approved_currency = st.selectbox("Approved currency", ["INR", "USD", "EUR", "GBP"], key="approved_currency")
            with ac2:
                approved_beneficiary = st.text_input("Approved beneficiary ID", value="BENEFICIARY-A")
        else:
            approved_amount = None
            approved_currency = None
            approved_beneficiary = None

        seen_ids = st.text_input("Previously processed request IDs (comma-separated)", value="")
        limits1, limits2, limits3 = st.columns(3)
        with limits1:
            per_limit = st.number_input("Per-transaction limit", min_value=1.0, value=100000.0, step=1000.0)
        with limits2:
            daily_total = st.number_input("Today's existing total", min_value=0.0, value=0.0, step=1000.0)
        with limits3:
            daily_limit = st.number_input("Daily limit", min_value=1.0, value=200000.0, step=1000.0)

        if st.button("Evaluate Transaction Controls", key="txn_eval"):
            try:
                result = evaluate_transaction(
                    request_id=request_id,
                    amount=amount,
                    currency=currency,
                    beneficiary_id=beneficiary,
                    session_valid=session_valid,
                    authenticated=authenticated,
                    step_up_verified=step_up,
                    approved_amount=approved_amount,
                    approved_currency=approved_currency,
                    approved_beneficiary_id=approved_beneficiary,
                    previously_seen_request_ids={
                        x.strip() for x in seen_ids.split(",") if x.strip()
                    },
                    is_new_beneficiary=new_beneficiary,
                    per_transaction_limit=per_limit,
                    daily_total=daily_total,
                    daily_limit=daily_limit,
                )
                record_activity("Transaction Simulation", result["verdict"], result["rule_ids"])
                show_decision(
                    result["verdict"],
                    result["message"],
                    result["rule_ids"]
                )
                st.warning("Simulation only: this result does not authenticate a real customer or execute a bank transaction.")
            except Exception as error:
                st.error("Transaction policy evaluation failed.")
                st.exception(error)


# --------------------------------------------------
# PAGE 6: SESSION ACTIVITY
# --------------------------------------------------


elif page == "Session Activity":

    st.markdown(
        '<div class="main-title">Session Activity</div>',
        unsafe_allow_html=True
    )
    st.markdown(
        '<div class="subtitle">Review decisions generated during this browser session.</div>',
        unsafe_allow_html=True
    )

    if st.session_state.activity:

        st.dataframe(
            list(reversed(st.session_state.activity)),
            use_container_width=True,
            hide_index=True
        )

        st.caption(
            "Only event metadata is stored here. "
            "Raw customer message text is not stored in this session history."
        )

        if st.button("Clear Session Activity"):
            st.session_state.activity = []
            st.session_state.scan_count = 0
            st.rerun()

    else:
        st.info(
            "No activity yet. Run a security scan or output validation first."
        )



# --------------------------------------------------
# PAGE 7: PERSISTENT AUDIT TRAIL
# --------------------------------------------------

elif page == "Audit Trail":

    st.markdown(
        '<div class="main-title">Audit Trail</div>',
        unsafe_allow_html=True
    )
    st.markdown(
        '<div class="subtitle">Local hash-chained decision metadata. No raw customer messages are stored.</div>',
        unsafe_allow_html=True
    )

    try:
        integrity = verify_chain()
        if integrity["valid"]:
            st.success(f"Hash-chain check passed. Events checked: {integrity['checked_events']}")
        else:
            st.error(f"Audit integrity check failed at sequence {integrity['failed_sequence']}.")

        events = read_events(limit=100)
        if events:
            st.dataframe(events, use_container_width=True, hide_index=True)
        else:
            st.info("No persistent audit events yet.")
        st.caption(
            "Demonstration-grade local SQLite audit log. A production deployment "
            "needs centralized access-controlled storage, retention controls, "
            "backup, monitoring and immutable/WORM storage."
        )
    except Exception as error:
        st.error("Audit storage is unavailable.")
        st.exception(error)


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "SecureFin Gateway | Deterministic BFSI Security Prototype | "
    "For demonstration and evaluation purposes"
)
