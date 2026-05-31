# Tombstone Orphan-Derived Handle Records

When a previously consumed Chain Event no longer belongs to the chosen Chain
View, the Coprocessor will perform Orphan Discard by tombstoning affected Handle
Records rather than physically deleting them. Tombstoned records are hidden from
normal resolution and API reads, but retained for auditability and reorg
debugging; orphaning is not represented as a Failed Handle State. Orphan
Discard cascades through the Handle Graph: any Derived Handle whose lineage
depends on an orphaned Handle Record is also tombstoned, even if its own
ChainEventRef still belongs to the current Chain View.
