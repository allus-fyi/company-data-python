"""The Python allus SDK example suite — ONE single-worker local server that
serves the shared portal frontend and implements the demo-backend contract (v3) for
all three scenario families:

    identity      — sign-in / OIDC / service-2FA (scenario ids 1–8)
    flow          — run a contract flow (flow:run)
    company-data  — connections / request fields / change feed / webhooks / documents
                    (the five companydata:*)

Shared scaffolding (runtime state, launcher, router, bundle fetch+verify, contract
guard, port guard, config-file model, run store, clear) lives at the package root;
each family's SCENARIO HANDLERS — which ARE the SDK example — live under
``handlers/``. Its own sub-project — not separately published, but its
source ships INSIDE the published SDK package (both the wheel and the sdist), so an
installing developer gets a runnable suite."""
