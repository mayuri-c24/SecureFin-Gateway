# SecureFin Gateway – BFSI Chatbot Security & Guardrails

A Python-based security and guardrail system designed to improve the safety, reliability, and control of chatbot interactions in the Banking, Financial Services, and Insurance (BFSI) domain.

## 1. Project Overview

SecureFin Gateway is a chatbot security framework that evaluates user inputs and chatbot outputs using rule-based security mechanisms.

Financial chatbots may encounter unsafe requests, unauthorized transaction instructions, misleading financial advice, and attempts to bypass security restrictions.

This project introduces a guardrail layer that analyzes interactions and applies appropriate security decisions before allowing responses to proceed.

## 2. Key Objectives

- Improve security in BFSI chatbot interactions.
- Detect potentially unsafe or unauthorized requests.
- Prevent inappropriate financial advice generation.
- Validate chatbot responses before displaying them.
- Maintain audit logs for security-related decisions.
- Provide structured security decisions for different interaction scenarios.

## 3. Key Features

### Input Guardrails
- User message evaluation.
- Detection of suspicious and adversarial inputs.
- Financial advice detection.
- Transaction security validation.

### Output Guardrails
- Validation of chatbot-generated responses.
- Detection of unsafe or inappropriate output.
- Response filtering based on security rules.

### Policy Decision Engine

The system supports structured security verdicts:

| Verdict | Description |
|---|---|
| ALLOW | Request is permitted. |
| ALLOW_CONSTRAINED | Request is permitted with restrictions. |
| BLOCK | Request is rejected. |
| ESCALATE | Request requires additional review. |
| REDACT | Sensitive content is masked or removed. |

### Additional Security Features
- Transaction security checks.
- Adversarial input testing.
- Financial advice detection.
- Audit logging.
- YAML-based policy rules.
- Automated test cases.

## 4. Technology Stack

- **Programming Language:** Python
- **User Interface:** Streamlit
- **Data Processing:** Pandas
- **Machine Learning Library:** Scikit-learn
- **Policy Configuration:** YAML
- **Testing Framework:** Pytest
- **Local LLM Integration:** Ollama (used by the chatbot pipeline)

## 5. Project Structure

```text
SecureFin-Gateway/
│
├── app.py
├── requirements.txt
├── README.md
├── ADVANCED_HARDENING_GUIDE.md
│
├── guardrails/
│   ├── __init__.py
│   ├── chatbot_pipeline.py
│   ├── policy_engine.py
│   ├── output_guardrail.py
│   ├── advice_detector.py
│   ├── transaction_security.py
│   ├── additional_scenarios.py
│   └── audit_logger.py
│
├── rules/
│   └── advice.yaml
│
├── tests/
│   ├── test_policy_engine.py
│   ├── test_output_guardrail.py
│   ├── test_chatbot_pipeline.py
│   ├── test_transaction_security.py
│   └── ...
│
├── evaluation/
│   ├── create_holdout_dataset.py
│   ├── evaluate_dataset.py
│   ├── evaluate_holdout.py
│   └── evaluate_unique_dataset.py
│
└── data/
    └── README.txt
```

## 6. Installation and Setup

### Step 1: Clone the repository

```bash
git clone https://github.com/mayuri-c24/SecureFin-Gateway.git
cd SecureFin-Gateway
```

### Step 2: Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\activate
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Ollama

The chatbot pipeline uses a locally running Ollama service with the `llama3.2:3b` model.

Install Ollama, download the model, and ensure the local service is running:

```bash
ollama pull llama3.2:3b
```

### Step 5: Run the application

```bash
streamlit run app.py
```

## 7. Running Tests

Execute the test suite using:

```bash
pytest -v
```

This runs the available automated tests for the project's guardrail components.

## 8. Evaluation

The repository includes Python scripts for dataset creation and evaluation:

- `create_holdout_dataset.py`
- `evaluate_dataset.py`
- `evaluate_holdout.py`
- `evaluate_unique_dataset.py`

These scripts support evaluation of the security and guardrail mechanisms.

Evaluation datasets and generated CSV reports are not included in the public repository. Use approved synthetic or de-identified datasets when running evaluation workflows.

## 9. Security Considerations

SecureFin Gateway is an academic and demonstration project.

It is not a certified banking security product and should not be deployed in a production financial environment without further security testing, independent validation, compliance review, and integration with appropriate authentication and authorization systems.

Never include real banking credentials, customer information, API keys, or confidential financial records in the project repository.

## 10. Future Scope

- Advanced multilingual threat detection.
- Stronger authentication and authorization integration.
- Expanded adversarial testing.
- Improved audit monitoring and reporting.
- Integration with secure banking APIs.
- Further evaluation across diverse financial interaction scenarios.

## 11. Author

**Mayuri Pratap Chinchole**

Electronics and Telecommunication Engineering

GitHub: https://github.com/mayuri-c24

---

**Project:** SecureFin Gateway – BFSI Chatbot Security & Guardrails

**Repository:** https://github.com/mayuri-c24/SecureFin-Gateway
