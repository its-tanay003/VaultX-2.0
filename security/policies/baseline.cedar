// VaultX 2.0 Baseline Capability Authorization Policies (Spec §8)

// Invariant: Quarantined or untrusted principals are unconditionally denied
forbid (
    principal,
    action,
    resource
)
when {
    context.trust_state == "quarantined" || context.trust_state == "untrusted"
};

// ==========================================
// 1. Viewer Role: Read-only inspection
// ==========================================
permit (
    principal in ValutX::Role::"Viewer",
    action == ValutX::Action::"project.read",
    resource
);

// ==========================================
// 2. Student Role: Local safe learning
// ==========================================
permit (
    principal in ValutX::Role::"Student",
    action in [
        ValutX::Action::"project.read",
        ValutX::Action::"project.write",
        ValutX::Action::"audit.export"
    ],
    resource
);

permit (
    principal in ValutX::Role::"Student",
    action == ValutX::Action::"terminal.execute",
    resource
)
when {
    context.environment == "sandbox"
};

permit (
    principal in ValutX::Role::"Student",
    action == ValutX::Action::"cyber.active_scan",
    resource
)
when {
    context.environment == "lab" && context.scope_valid
};

// ==========================================
// 3. Developer Role: Engineering & Building
// ==========================================
permit (
    principal in ValutX::Role::"Developer",
    action in [
        ValutX::Action::"project.read",
        ValutX::Action::"project.write",
        ValutX::Action::"audit.export",
        ValutX::Action::"background_agent"
    ],
    resource
);

permit (
    principal in ValutX::Role::"Developer",
    action == ValutX::Action::"terminal.execute",
    resource
)
when {
    context.environment == "sandbox"
};

permit (
    principal in ValutX::Role::"Developer",
    action == ValutX::Action::"network.external",
    resource
)
when {
    context.environment == "sandbox" || context.scope_valid
};

permit (
    principal in ValutX::Role::"Developer",
    action == ValutX::Action::"cyber.active_scan",
    resource
)
when {
    context.environment == "lab" && context.scope_valid
};

permit (
    principal in ValutX::Role::"Developer",
    action == ValutX::Action::"secrets.use",
    resource
)
when {
    context.scope_valid
};

permit (
    principal in ValutX::Role::"Developer",
    action == ValutX::Action::"plugin.install",
    resource
)
when {
    context.approval_valid
};

// ==========================================
// 4. Security Analyst: Scoped Auditing & Pentest
// ==========================================
permit (
    principal in ValutX::Role::"SecurityAnalyst",
    action in [
        ValutX::Action::"project.read",
        ValutX::Action::"project.write",
        ValutX::Action::"background_agent"
    ],
    resource
);

permit (
    principal in ValutX::Role::"SecurityAnalyst",
    action == ValutX::Action::"terminal.execute",
    resource
)
when {
    context.environment == "sandbox"
};

permit (
    principal in ValutX::Role::"SecurityAnalyst",
    action in [
        ValutX::Action::"network.external",
        ValutX::Action::"cyber.active_scan",
        ValutX::Action::"secrets.use",
        ValutX::Action::"audit.export"
    ],
    resource
)
when {
    context.scope_valid
};

permit (
    principal in ValutX::Role::"SecurityAnalyst",
    action == ValutX::Action::"plugin.install",
    resource
)
when {
    context.approval_valid
};

// ==========================================
// 5. Admin Role: Full Administrative Control
// ==========================================
permit (
    principal in ValutX::Role::"Admin",
    action,
    resource
);
