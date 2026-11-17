/**
 * The decision model's answers as hypothesis templates read them.
 *
 * The knowledge base asks Jev (a decision model) fixed questions about every function and keeps
 * one answer per question: a yes/no probability, or a chosen option. Templates read those answers
 * and nothing else of the model, so this module declares the shape itself instead of importing
 * the knowledge base's client.
 */

/** One answer: a yes/no probability, or the option chosen. */
export type Label = { type: 'noul'; noul: number } | { type: 'choice'; choice: string };
/** Every answer about one function, by question name. */
export type Labels = Record<string, Label>;

/** The probability of a yes/no answer, 0 when the question went unanswered. */
export function yes(labels: Labels | undefined, name: string): number {
  const label = labels?.[name];
  return label?.type === 'noul' ? label.noul : 0;
}

/** The chosen option of a choice answer, 'none' when the question went unanswered. */
export function chosen(labels: Labels | undefined, name: string): string {
  const label = labels?.[name];
  return label?.type === 'choice' ? label.choice : 'none';
}
