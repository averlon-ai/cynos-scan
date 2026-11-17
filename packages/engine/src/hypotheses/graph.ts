/**
 * Graph searches the templates share: over the code graph's calls, or over any name-to-name
 * relation a template builds (a macro's calls, for instance).
 */

/** Who calls each callee: `[caller, callee]` pairs turned around, self-calls left out. */
export function callersOf(calls: Iterable<[string, string]>): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const [caller, callee] of calls)
    if (caller !== callee) out.set(callee, (out.get(callee) ?? new Set()).add(caller));
  return out;
}

/** What each caller calls, in call order, self-calls left out. */
export function calleesOf(calls: Iterable<[string, string]>): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const [caller, callee] of calls)
    if (caller !== callee) out.set(caller, [...(out.get(caller) ?? []), callee]);
  return out;
}

/**
 * Every node that reaches a root through its callees, mapped to the next node on its shortest way
 * there (a root maps to itself). Breadth first from the roots, so each node keeps its shortest
 * path, and every node is visited once: the fixed point of "a caller of a node that reaches a
 * root reaches it too".
 */
export function propagateToCallers(
  roots: Iterable<string>,
  callers: Map<string, Set<string>>
): Map<string, string> {
  const via = new Map<string, string>();
  const queue: string[] = [];
  for (const root of roots)
    if (!via.has(root)) {
      via.set(root, root);
      queue.push(root);
    }
  for (let i = 0; i < queue.length; i++) {
    const node = queue[i] as string;
    for (const caller of callers.get(node) ?? []) {
      if (via.has(caller)) continue;
      via.set(caller, node);
      queue.push(caller);
    }
  }
  return via;
}

/** The path from `node` to its root along `via` (propagateToCallers), at most `max` steps. */
export function pathToRoot(node: string, via: Map<string, string>, max: number): string[] {
  const path = [node];
  while (path.length < max) {
    const last = path[path.length - 1] as string;
    const next = via.get(last);
    if (next === undefined || next === last) break;
    path.push(next);
  }
  return path;
}

/** Every node reachable from `starts` within `depth` calls, with its distance (starts are 0). */
export function reachable(
  starts: Iterable<string>,
  callees: Map<string, string[]>,
  depth: number
): Map<string, number> {
  const distance = new Map<string, number>();
  const queue: string[] = [];
  for (const start of starts)
    if (!distance.has(start)) {
      distance.set(start, 0);
      queue.push(start);
    }
  for (let i = 0; i < queue.length; i++) {
    const node = queue[i] as string;
    const d = distance.get(node) as number;
    if (d >= depth) continue;
    for (const next of callees.get(node) ?? [])
      if (!distance.has(next)) {
        distance.set(next, d + 1);
        queue.push(next);
      }
  }
  return distance;
}
