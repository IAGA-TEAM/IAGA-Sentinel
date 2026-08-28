//! The sandbox SQL classifier must not read a read-only SELECT as destructive.
//!
//! `analyze_db` matched `DELETE`/`DROP`/`UPDATE`/`ALTER` as SUBSTRINGS of the
//! uppercased query, so ordinary column names -- `deleted_at`, `dropbox_url`,
//! `updated_at`, `alternate_id` -- classified a `SELECT` as a critical,
//! irreversible DELETE with a fabricated "~10000 rows affected".
//!
//! Nothing signed moves: the composite risk formula has no sandbox term, and
//! `layer_roles()` publishes `sandboxResult` as advisory. What it did move is
//! `requires_approval`, which is what puts an entry in front of a human on
//! `/v1/sandbox/pending` and on the console. A queue full of destructive-looking
//! reads is how an operator stops reading the queue.
//!
//! Its own binary: `sandbox_execute` writes to the process-global PENDING map,
//! and `tests/unit_tests.rs` already leaves an entry there permanently.

use iaga_sentinel::modules::sandbox::sandbox_executor::{
    prune_stale_pending, sandbox_execute, should_sandbox,
};

fn severity_of(query: &str) -> String {
    let payload = serde_json::json!({ "query": query });
    // Risk below every `should_sandbox` threshold so the call cannot land in
    // PENDING and pollute the other tests in this binary.
    sandbox_execute("db.query", "db_query", &payload, 10)
        .impact
        .severity
}

#[test]
fn a_column_named_deleted_at_is_not_a_delete() {
    assert_eq!(
        severity_of("SELECT id, name FROM users WHERE deleted_at IS NULL"),
        "low",
        "`deleted_at` is a column, not a DELETE statement"
    );
}

#[test]
fn ordinary_column_names_are_not_destructive_statements() {
    for query in [
        "SELECT dropbox_url FROM files",
        "SELECT * FROM orders ORDER BY updated_at DESC",
        "SELECT alternate_id FROM skus",
        "SELECT undeleted, dropped_count, updating FROM metrics",
    ] {
        assert_eq!(
            severity_of(query),
            "low",
            "read-only query classified as destructive: {query}"
        );
    }
}

/// Coverage must not be lost: the statements this layer exists to catch are
/// still caught, in either case, and with or without a WHERE.
#[test]
fn real_mutations_are_still_classified() {
    for (query, want) in [
        ("DELETE FROM users", "critical"),
        ("delete from users where id = 1", "high"),
        ("DROP TABLE users", "critical"),
        ("UPDATE users SET name = 'x' WHERE id = 1", "medium"),
        ("ALTER TABLE users ADD COLUMN x INT", "high"),
    ] {
        assert_eq!(severity_of(query), want, "missed a real mutation: {query}");
    }
}

#[test]
fn a_real_delete_still_reports_its_operation() {
    let payload = serde_json::json!({ "query": "DELETE FROM sessions" });
    let result = sandbox_execute("db.query", "db_query", &payload, 10);

    assert_eq!(result.db_operations.len(), 1);
    assert_eq!(result.db_operations[0].op_type, "DELETE");
    assert!(!result.db_operations[0].reversible);
}

/// A read-only SELECT must not reach the human approval queue at all.
#[test]
fn a_read_only_select_does_not_require_approval() {
    let payload =
        serde_json::json!({ "query": "SELECT id FROM invoices WHERE deleted_at IS NULL" });
    // 55 is over the db_query threshold in `should_sandbox`, so the sandbox
    // genuinely runs; only the classifier decides whether a human is summoned.
    assert!(should_sandbox("db_query", 55));
    let result = sandbox_execute("db.query", "db_query", &payload, 55);

    assert!(
        !result.requires_approval,
        "a read-only SELECT must not be queued for a human: {:?}",
        result.impact
    );
}

/// FINDING 2.6: the queue is prunable. It previously shrank only when an admin
/// approved or rejected, so it grew without bound for the life of the process.
#[test]
fn the_pending_queue_can_be_pruned() {
    let payload = serde_json::json!({ "command": "rm -rf /tmp/x" });
    let queued = sandbox_execute("shell.run", "shell", &payload, 90);
    assert!(
        queued.requires_approval,
        "precondition: this must be queued"
    );

    // TTL of 0: everything is already older than "no age at all".
    let pruned = prune_stale_pending(0);
    assert!(
        pruned >= 1,
        "prune_stale_pending must drop expired approval requests, dropped {pruned}"
    );
}
