/**
 * The interface between hypothesis templates and whatever runs them.
 *
 * A hypothesis is a question the build asks before the scan, from facts no single file shows, for
 * one helper of the scan to settle either way. A template is one kind of such question. It
 * defines three things:
 *
 *   questions   what to ask the decision model about every function; the caller asks them and
 *               hands back the answers as labels
 *   hypotheses  the queries over the code graph and those labels that turn facts into hypotheses,
 *               each with a claim, where it starts, what would settle it, and the files the brief
 *               of the packet that settles it is built from
 *   section     optional facts for every helper's brief, about the files that brief covers
 *
 * Everything is plain data in and out: no model client, no file system, nothing of the knowledge
 * base. A caller that can supply files, functions, calls and answers can run any template.
 *
 * The examples below follow one made-up template through every type: an online shop whose order
 * page may show any customer's order. Its route handler takes the order id from the URL and loads
 * the order; whether anything on the way checks that the order belongs to the logged-in customer
 * is a question no single file answers, since the route, the service and the query live in three.
 *
 *   orders/routes.py    get_order(order_id)      route handler: GET /orders/<order_id>
 *   orders/service.py   fetch_order(order_id)    called by get_order
 *   orders/repo.py      load_order(order_id)     SELECT ... WHERE id = :order_id
 *
 * The template asks of every function "does it load a record by an id the caller supplies?" and
 * "does it check that the record belongs to the caller?", follows the calls from each route
 * handler to a function that loads by id, and makes a hypothesis of every such path on which no
 * function checks ownership.
 */
import type { Labels } from './labels';
import type { SourceFunction } from './source';

/**
 * A question the decision model answers about one function, given the function's source.
 *
 * The caller asks every template's questions about every function, in the same call as its own
 * questions, so a function is read once; the answers come back as that function's `Labels`, under
 * the question's `name`. A yes/no question (`noul`) is answered with the probability of yes, a
 * `choice` with the option chosen.
 *
 * ```ts
 * const LOADS_BY_ID: LabelQuestion = {
 *   name: 'loads_by_id',
 *   type: 'noul',
 *   instructions: 'Does this function load a stored record by an id its caller passes in?',
 *   criteria: {
 *     true: 'It reads a record (a row, a document, a file) selected by an id it was given.',
 *     false: 'It reads nothing by id, or only by an id it made itself.',
 *   },
 * };
 * // load_order's labels then hold  loads_by_id: { type: 'noul', noul: 0.94 }
 * ```
 *
 * Two templates may share a question: they then declare the same object, or an identical one, so
 * that it is asked once (`labelQuestions` throws when two differ under one name).
 */
export interface LabelQuestion {
  /** The answer's name in `Labels`, unique across every template: `loads_by_id`. */
  name: string;
  /** `noul`: a yes/no answered with the probability of yes. `choice`: one option of `criteria`. */
  type: 'noul' | 'choice';
  /** The question, as the decision model reads it beside the function's source. */
  instructions: string;
  /**
   * What each answer means. For `noul`, the keys `true` and `false`; for `choice`, one key per
   * option, which is the value the answer carries:
   *
   * ```ts
   * criteria: { order: 'An order.', user: 'A user account.', other: 'Any other record.' }
   * // answered as { type: 'choice', choice: 'order' }
   * ```
   */
  criteria: Record<string, string>;
  /**
   * Ask this question only of the functions whose earlier answers make it matter. The decision
   * model has no conditional questions, so the caller asks in two passes: first every question
   * without `askIf` of every function, then this one alone of each function for which `askIf`
   * holds on its first-pass labels. Most functions load nothing by id, so asking which kind of
   * record they load would be thousands of calls whose answers mean nothing:
   *
   * ```ts
   * const RECORD_KIND: LabelQuestion = {
   *   name: 'record_kind',
   *   type: 'choice',
   *   instructions: 'Which kind of record does this function load by id?',
   *   criteria: { order: 'An order.', user: 'A user account.', other: 'Any other record.' },
   *   askIf: labels => yes(labels, 'loads_by_id') >= 0.3,
   * };
   * // asked of load_order (loads_by_id 0.94), not of format_price (0.01)
   * ```
   *
   * Unset: asked of every function in the first pass.
   */
  askIf?: (labels: Labels | undefined) => boolean;
}

/**
 * What a template reads: the repository's text, its functions and calls from the code graph, and
 * the answers about every function. Function names are qualified names (`qn`), unique in the
 * graph; calls and labels refer to functions by them.
 *
 * ```ts
 * const input: HypothesisInput = {
 *   files: [{ path: 'orders/routes.py', text: '@app.get("/orders/<order_id>")\ndef get_order(' }],
 *   functions: [
 *     { qn: 'orders.routes.get_order', name: 'get_order',
 *       path: 'orders/routes.py', start: 1, end: 6 },
 *     { qn: 'orders.service.fetch_order', name: 'fetch_order',
 *       path: 'orders/service.py', start: 3, end: 9 },
 *     { qn: 'orders.repo.load_order', name: 'load_order',
 *       path: 'orders/repo.py', start: 5, end: 8 },
 *   ],
 *   calls: [
 *     ['orders.routes.get_order', 'orders.service.fetch_order'],
 *     ['orders.service.fetch_order', 'orders.repo.load_order'],
 *   ],
 *   labels: new Map([
 *     ['orders.routes.get_order', { entry_point: { type: 'noul', noul: 0.97 } }],
 *     ['orders.repo.load_order', { loads_by_id: { type: 'noul', noul: 0.94 } }],
 *   ]),
 * };
 * ```
 */
export interface HypothesisInput {
  /** Every text file of the repository, by repository-relative path. */
  files: { path: string; text: string }[];
  /** Every function and method the code graph found, with its file and 1-based line range. */
  functions: SourceFunction[];
  /** `[caller qn, callee qn]`, repository code only: one entry per pair, however many calls. */
  calls: [string, string][];
  /**
   * Every answer about each function, by qn: the templates' own questions and the caller's. The
   * caller's include `entry_point`, a yes/no (can an outside caller invoke this function
   * directly: a route handler, an RPC method, a CLI command?), and `sink`, a choice of the
   * sensitive operation it performs (`database`, `filesystem`, `execution`, `network`,
   * `rendering`, `crypto` or `none`). A question that went unanswered is missing; read the labels
   * with `yes()` and `chosen()` (labels.ts), which treat a missing answer as no and as none.
   */
  labels: Map<string, Labels>;
}

/**
 * The focus and files of the investigation packet that settles a hypothesis: the caller turns it
 * into a packet's brief, as it does for the packets the scan plans itself.
 *
 * ```ts
 * const brief: HypothesisBrief = {
 *   perspective: 'Who may read which order: each order route, down to the query that loads it.',
 *   attacker: 'A logged-in customer who changes the order id in the URL.',
 *   seeds: ['orders/routes.py', 'orders/service.py', 'orders/repo.py'],
 *   related: ['auth/session.py'],
 * };
 * ```
 */
export interface HypothesisBrief {
  /** What the packet looks at, printed at the top of its brief. */
  perspective: string;
  /** Who the packet assumes attacks, printed under the perspective. */
  attacker: string;
  /**
   * The files to print in full, first in the brief's core and in this order, within the core's
   * token budget: the files the hypothesis is about.
   */
  seeds: string[];
  /**
   * Other files the packet will need, not printed but listed in the brief's map for the helper to
   * load when its review leads there. The caller adds the files of every packet of the scan that
   * reviews the first seed.
   */
  related: string[];
}

/**
 * One question for a helper to settle: a claim that may or may not hold, where to start, and what
 * would settle it either way. It is not a finding; the helper reports a finding only if it
 * establishes the claim from the code, and otherwise records why it does not hold.
 *
 * ```ts
 * const hypothesis: Hypothesis = {
 *   template: 'missing-ownership-check',
 *   claim:
 *     '`get_order` (GET /orders/<order_id>) loads an order by the id in the URL through ' +
 *     '`fetch_order` and `load_order`, and none of the three checks that the order belongs to ' +
 *     'the logged-in customer.',
 *   where: 'orders/routes.py:1',
 *   check:
 *     "Follow the order id from the route to the query: does any step compare the order's " +
 *     'customer with the session\'s, or filter the query by it? Name the line if one does; if ' +
 *     "none does, any customer can read another's order by its id.",
 *   brief,
 * };
 * ```
 */
export interface Hypothesis {
  /** The `id` of the template that made it; hypotheses of one template are packed together. */
  template: string;
  /** What may be true, with the names and the facts that make it worth a look. */
  claim: string;
  /** `path:line` where the investigation starts. */
  where: string;
  /** What would settle the hypothesis, either way. */
  check: string;
  /**
   * The packet's focus and files. Hypotheses computed from the same facts (two routes into one
   * query, say) share one brief, the same object, so a packet given both builds one brief.
   */
  brief: HypothesisBrief;
}

/**
 * One kind of hypothesis: the questions it needs answered, the queries that turn the answers into
 * hypotheses, and optionally facts for every helper's brief. A template module exports one object
 * of this type per kind; register it in `TEMPLATES` (index.ts).
 *
 * ```ts
 * export const MISSING_OWNERSHIP_CHECK: HypothesisTemplate = {
 *   id: 'missing-ownership-check',
 *   description: 'A route loads a record by a caller-supplied id and nothing checks its owner.',
 *   questions: [LOADS_BY_ID, CHECKS_OWNER, RECORD_KIND],
 *   hypotheses: input =>
 *     routeHandlers(input)                                // entry_point >= 0.3
 *       .flatMap(route => pathsTo(route, loadsById, input)) // calls, a few levels deep
 *       .filter(path => !path.some(checksOwner))           // checks_owner < 0.3 at every step
 *       .map(path => hypothesisOf(path)),
 *   briefSection: (input, files) => recordsLoadedById(input, files), // "## Records loaded by id"
 * };
 * ```
 */
export interface HypothesisTemplate {
  /** A short kebab-case name, unique among the templates: `missing-ownership-check`. */
  id: string;
  /** One line: the kind of bug it looks for. */
  description: string;
  /** The questions its queries read the answers to, asked of every function (see LabelQuestion). */
  questions: LabelQuestion[];
  /**
   * The hypotheses the repository's facts support, or none. A pure function of its input: it
   * reads the labels, follows the calls and reads the files' text, and makes up nothing it cannot
   * point at. It returns an empty list when the facts it needs are not there (no route handler
   * loads anything by id), which is the usual answer for a repository it does not fit.
   */
  hypotheses(input: HypothesisInput): Hypothesis[];
  /**
   * Facts for a brief that covers `files`, as markdown lines under a `## ` heading of their own,
   * or none when none of its facts concern those files. Every brief of the scan gets them, not
   * only the hypothesis packets', so a helper reviewing those files sees the same facts:
   *
   * ```md
   * ## Records loaded by id
   *
   * - `load_order` (`orders/repo.py:5`): an order, by the id its caller passes
   * ```
   *
   * Templates that share one section function share the section: it is printed once.
   */
  briefSection?(input: HypothesisInput, files: ReadonlySet<string>): string[];
}
