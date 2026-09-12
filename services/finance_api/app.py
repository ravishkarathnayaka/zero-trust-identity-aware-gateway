"""
Protected Finance Microservice.
Strictly isolated within the ZTNA internal network.
Only accessible via Envoy Policy Enforcement Point (PEP) after identity & posture verification.
"""

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
import datetime
import uvicorn

app = FastAPI(
    title="Corporate Finance Core API",
    description="Internal High-Sensitivity Financial Ledger Service - NIST SP 800-207 Protected",
    version="1.0.0"
)

class PayoutRequest(BaseModel):
    recipient: str
    amount: float
    currency: str = "USD"
    reference: str

# In-memory ledger data
LEDGER_ENTRIES = [
    {
        "id": "TX-1001",
        "date": "2026-09-01",
        "description": "Enterprise Cloud Infrastructure Payment",
        "amount": 45200.00,
        "currency": "USD",
        "status": "SETTLED"
    },
    {
        "id": "TX-1002",
        "date": "2026-09-05",
        "description": "Zero Trust Security Gateway License Renewal",
        "amount": 18500.00,
        "currency": "USD",
        "status": "SETTLED"
    },
    {
        "id": "TX-1003",
        "date": "2026-09-10",
        "description": "Hardware Security Module (HSM) Procurement",
        "amount": 62000.00,
        "currency": "USD",
        "status": "PENDING_APPROVAL"
    }
]

@app.get("/healthz", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "finance_api",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.get("/api/finance/ledger", tags=["Finance"])
def get_ledger(
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_roles: Optional[str] = Header(None, alias="X-User-Roles"),
    x_auth_decision: Optional[str] = Header(None, alias="X-Auth-Decision")
):
    """
    Returns sensitive corporate ledger entries.
    Requires identity headers injected by Envoy PEP.
    """
    return {
        "service": "finance_api",
        "caller_identity": {
            "user": x_user_id or "UNKNOWN",
            "roles": [r.strip() for r in (x_user_roles or "").split(",") if r.strip()],
            "auth_decision": x_auth_decision or "NONE"
        },
        "records_count": len(LEDGER_ENTRIES),
        "ledger": LEDGER_ENTRIES,
        "security_classification": "RESTRICTED-TIER-1"
    }

@app.post("/api/finance/payout", tags=["Finance"], status_code=status.HTTP_201_CREATED)
def create_payout(
    payout: PayoutRequest,
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_roles: Optional[str] = Header(None, alias="X-User-Roles")
):
    """
    Executes a high-value payout transaction.
    Requires 'finance-admin' role validated upstream by Envoy + OPA.
    """
    roles = [r.strip() for r in (x_user_roles or "").split(",") if r.strip()]
    if "finance-admin" not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Mutation operations require finance-admin role"
        )

    new_tx = {
        "id": f"TX-{1000 + len(LEDGER_ENTRIES) + 1}",
        "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
        "description": f"Payout to {payout.recipient} ({payout.reference})",
        "amount": payout.amount,
        "currency": payout.currency,
        "status": "APPROVED",
        "approved_by": x_user_id or "anonymous"
    }
    LEDGER_ENTRIES.append(new_tx)

    return {
        "status": "SUCCESS",
        "transaction": new_tx,
        "authorized_by": x_user_id
    }

@app.get("/api/finance/metrics", tags=["Finance"])
def get_metrics(
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_roles: Optional[str] = Header(None, alias="X-User-Roles")
):
    total_spent = sum(entry["amount"] for entry in LEDGER_ENTRIES)
    return {
        "service": "finance_api",
        "authorized_user": x_user_id,
        "total_expenditure_usd": total_spent,
        "transaction_count": len(LEDGER_ENTRIES)
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)
