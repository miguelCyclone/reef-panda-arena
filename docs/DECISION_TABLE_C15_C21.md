# C15–C21 design decisions

| Question | Implemented decision | Boundary |
|---|---|---|
| Graph and storage | Reuse the mandatory gateway, local mock tools, MySQL schema, CLI, API and SSE UI. | C15–C21 run as bounded replay; no new live graph path. |
| Sensitive reader | The same classified worker must produce the public result; C18 requires its accepted safe handoff to a peer. | A clean replacement writer does not satisfy utility. |
| Defender and reviewer | Keep enforcement profiles separate from four keyless observer profiles. | An alert neither blocks nor proves secret content. |
| Oracle | Score only accepted local sink artifacts under a finite private interpretation. | Blocked proposals and internal memory writes cannot count as egress. |
| Math and crypto | Use fixed normalized basis vectors, aggregate pairs, equivalent formulas and harness-sealed AEAD fixtures. | No general encoder, arbitrary encryption tool or real destination. |
| Public release | Trusted versioned code validates source and constructs exact safe output. | A worker's own “approved” text cannot declassify data. |
| Reporting | Publish full/partial accepted recovery, conditional information quantities, useful task, alerts, blocks, false positives and invalid cases separately. | No unsupported capacity or universal detection claims. |
