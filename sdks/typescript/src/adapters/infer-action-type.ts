import type { ActionType } from "../types";

/**
 * Guess an action type from a tool name.
 *
 * A framework hands the adapter a tool NAME, never an action type. Declaring
 * the type explicitly is always better than guessing; this is the fallback for
 * the adapters that have nothing else to go on.
 *
 * Order is load-bearing: `write` is tested before `read`/`file` (otherwise
 * `write_file` reads as a file_read and is scored at 15 instead of 40), and the
 * shell branch covers `bash` (otherwise `Bash`, the single most common tool
 * name in the ecosystem, falls through to `custom` and is scored at 25 instead
 * of 60). The Python SDK's `infer_action_type` mirrors this for the names that
 * collide, so one policy can govern both runtimes.
 *
 * This lived as a byte-identical copy in `langgraph.ts` and `mcp.ts`. Not
 * exported from the package index -- it is internal to the adapters, so sharing
 * it is a pure-internal change with no public API surface.
 *
 * Deliberately NOT shared with `@iaga-sentinel/voltagent-plugin`'s
 * `defaultInferActionType`: that is a separate npm package with a deliberately
 * different heuristic (it returns `db_query` and `email`, and its own tests pin
 * a different precedence). Merging them would change behaviour.
 */
export function inferActionType(name: string): ActionType {
  const n = name.toLowerCase();
  if (/(shell|bash|terminal|exec|command)/.test(n)) return "shell";
  if (/(http|fetch|web|url|request)/.test(n)) return "http";
  if (/(write|edit|create|delete)/.test(n)) return "file_write";
  if (/(read|file|glob|grep|cat|list)/.test(n)) return "file_read";
  return "custom";
}
