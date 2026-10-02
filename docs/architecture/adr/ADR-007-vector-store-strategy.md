# ADR-007: Vector Store Strategy Decided by Phase 4 Technical Spike

- **Status**: Proposed
- **Deciders**: Product Owner, Security & Architecture Team
- **Date**: 2026-10-02
- **Technical Story**: Task P0-T03 — Write and ratify ADR-002 to ADR-009.
- **Governs**: `services/context-engine`, local RAG subsystem.

---

## Context and Problem Statement

VaultX 2.0 requires semantic code search, AST indexing, and documentation retrieval operating fully offline on developer laptops (Sprint 7). Spec §42 lists vector store selection as an open architecture decision with three candidates:
1. `sqlite-vec` (pure SQLite extension).
2. `LanceDB` (embedded serverless columnar vector database).
3. `Qdrant embedded` (in-process Rust vector database).

Selecting a heavy vector database prematurely could bloat desktop packaging, while an overly simplistic store might fail to scale to 500,000-line repositories.

---

## Decision

We establish an **Interface-First Architecture** and defer physical storage engine selection to a dedicated **Phase 4 Technical Spike**:

1. **Unified Storage Trait**:
   - `services/context-engine` and `crates/runtime-core` define an abstract `VectorStore` trait:
     ```rust
     pub trait VectorStore: Send + Sync {
         async fn insert(&self, entries: Vec<EmbeddingEntry>) -> Result<(), StoreError>;
         async fn search(&self, query_vector: &[f32], limit: usize) -> Result<Vec<SearchResult>, StoreError>;
         async fn delete_by_project(&self, project_id: &str) -> Result<(), StoreError>;
     }
     ```
2. **Phase 4 Spike Criteria**:
   - During Phase 4 (Sprint 7), execute a formal benchmark comparing `sqlite-vec`, `LanceDB`, and `Qdrant embedded` against:
     - Memory footprint under a 50,000-chunk repository.
     - Cold startup time and query latency (<20ms target).
     - Cross-platform stability on Windows 11 and Linux without external daemons.
3. **Interim Baseline**:
   - During Sprints 0–6, context queries will use exact text search (ripgrep/BM25) and simple in-memory vector mocks, allowing development of orchestrator pipelines without blocking on vector database selection.

---

## Architectural Critique & Challenges

- **Challenge**: Deferring the vector store decision must not lead to teams writing ad-hoc storage code that later requires massive rewrites.
- **Resolution**: The `VectorStore` trait interface is ratified now in Sprint 0. All code written in Sprints 1–6 interacts solely with the trait, making the Phase 4 engine selection a simple drop-in adapter.

---

## Alternatives Considered

- **Committing to LanceDB immediately**: Considered. LanceDB is fast and modern, but has rapid API evolution and native library build complexities on some Windows environments.
- **Committing to SQLite-vec immediately**: Considered. Excellent portability and zero additional files, but lacks advanced filtering and clustering capabilities for large enterprise repos.

---

## Consequences

### Positive
- Avoids premature commitment to a vector storage engine before repository indexing performance is measured.
- Zero external daemon requirements for local-first execution.

### Negative
- Semantic vector retrieval is stubbed until Sprint 7 (Phase 4), relying on AST and lexical search during early sprints.

---

## Security Impact

Directly supports **Invariant 6** and **Invariant 8**. Ensures vector embeddings of proprietary code remain stored exclusively on local disk with zero external API leakage.

---

## Revisit Trigger

**Revisit when**:
- Phase 4 Spike benchmark results are completed in Sprint 7.
