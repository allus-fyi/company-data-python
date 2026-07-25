"""The Python company-data example backend (demo-backend contract v3).

A thin single-worker localhost server that serves the SAME shared frontend as the
PHP company-data example and implements the five ``companydata:*`` scenarios
against the SERVICE-role data :class:`allus_company_data.Client`:

    companydata:read        — Client.connections()   → connection-grouped values
    companydata:definitions — Client.request_fields() → your request-field catalog
    companydata:changes     — Client.process_changes() → crash-safe pump drain
    companydata:webhook     — verify_webhook()+parse_webhook() public receiver
                              + a drain_batch() feed fallback (accumulating run)
    companydata:documents   — Client.create_document() ×6 document/contract types
"""
