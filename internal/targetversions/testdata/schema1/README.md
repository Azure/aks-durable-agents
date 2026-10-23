# Schema-1 compatibility database

`golden.db` is an immutable SQLite fixture created through the real
Create/RegisterTarget/Begin/MarkPrepared/Reserve APIs at
`a3ef19a04165b6e46fe23e9bc993eac3c1ef2f4e`, then closed before saving its bytes.
It contains synthetic actor/decision/qualification/receipt evidence, a pending
reserved operation, and four history events. It contains no credentials or
real runtime effects.

`TestSchema1GoldenStoreStillOpens` copies it into an owner-private temporary
file and verifies identity, reserved evidence, history and repeated reopen
without changing the bytes. It must not be regenerated just to accommodate an
incompatible shared record change. Serialized field additions, ordering, types
or JSON tags in shared records require an explicit schema bump and reviewed
migration/refusal plan, with the old fixture retained to test that decision.

Moving unchanged record definitions to an internal shared package changes no
serialized shape. The fixture remains schema 1 and opens through that move.
This is a bounded compatibility regression, not hardware durability, live
activation, cross-store restore or rollback-resistance qualification.
