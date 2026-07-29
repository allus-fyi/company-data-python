"""Customer-role output models.

A CUSTOMER is the connecting company consuming/answering another company's
service. Its ``GET /api/company-connections`` payload has a different shape from
the service-side company-data feed: one row per company↔company pair, each with
the plaintext company profile + per-service shared values, the customer's own
answered mappings (metadata only — the customer typed those values, they are not
re-read), pending consents, and any issued documents.

These models are deliberately thin wrappers over the raw API dicts; the plaintext
fields (company identity, shared values, company profile) are exposed directly and
the ``raw`` dict is always kept for anything not surfaced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class CustomerServiceLink:
    """One service the customer is connected to, inside a :class:`CustomerConnection`."""

    service_link_id: Optional[str]
    service_id: Optional[str]
    service_name: Optional[str]
    service_code: Optional[str]
    shared: List[dict] = field(default_factory=list)       # plaintext {slug,label,type,value}
    mappings: List[dict] = field(default_factory=list)      # the customer's answered slots (metadata)
    pending_consent: Any = None
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(cls, obj: dict) -> "CustomerServiceLink":
        return cls(
            service_link_id=obj.get("service_link_id") or obj.get("id"),
            service_id=obj.get("service_id"),
            service_name=obj.get("service_name") or obj.get("name"),
            service_code=obj.get("service_code") or obj.get("share_code"),
            shared=obj.get("shared") or [],
            mappings=obj.get("mappings") or [],
            pending_consent=obj.get("pending_consent"),
            raw=obj,
        )


@dataclass
class CustomerConnection:
    """One company↔company connection from the customer's side."""

    id: Optional[str]
    company_user_id: Optional[str]
    company_name: Optional[str]
    company_code: Optional[str]
    customer_type: Optional[str]                            # "company" for a b2b link
    company_profile: List[dict] = field(default_factory=list)   # plaintext {slug,label,type,value}
    services: List[CustomerServiceLink] = field(default_factory=list)
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(cls, obj: dict) -> "CustomerConnection":
        company = obj.get("company") or {}
        services = [CustomerServiceLink.from_api(s) for s in (obj.get("services") or []) if isinstance(s, dict)]
        return cls(
            id=obj.get("id") or obj.get("company_connection_id"),
            company_user_id=obj.get("company_user_id") or company.get("user_id"),
            company_name=obj.get("company_name") or company.get("display_name"),
            company_code=obj.get("company_code") or company.get("share_code"),
            customer_type=obj.get("customer_type"),
            company_profile=obj.get("company_profile") or [],
            services=services,
            raw=obj,
        )

    @classmethod
    def list_from_api(cls, body: Any) -> List["CustomerConnection"]:
        if isinstance(body, dict):
            items = body.get("connections") or body.get("items") or []
        else:
            items = body or []
        return [cls.from_api(o) for o in items if isinstance(o, dict)]
