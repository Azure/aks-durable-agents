# Decision-ledger copied-record conformance fixtures

These six JSON files are unmodified records emitted by the actual
`decisionledger.Service.Decide`, not hand-authored approvals. The producer is
[decision-ledger PR #35](https://github.com/Azure/aks-durable-agents/pull/35),
commit `8f640ccbfbf4056b94c881d94822df65e44381dd`.

The producer ran with synthetic request verifier/policy fixtures (no real
credentials, people, or model/tool calls). Cases cover canonical evidence, a
policy-selected `Approver` role, a Unicode workspace and policy revision, and
subject/grant identifiers longer than 128 bytes. No role, identifier or other
field was rewritten after emission.

`TestDecisionLedgerRecordConformance` consumes these records through
Begin/Reserve/Commit and checks that recorded evidence remains unchanged.
The same cases were also run directly against the real producer Service and
consumer in an isolated combined checkout. This retains an ordinary-CI copied
contract test without importing unmerged producer code into this branch.

Only the copied record domain is qualified here. The owning adapter must still
read and compare the complete retained subject, exact target incarnation,
predecessor, candidate and qualification; verify current policy and credentials;
and enforce runtime fences. A local committed record proves no live activation.
Effect consumption and synthetic rollback/recovery/abandonment actions remain
unsupported by the initial producer contract.
