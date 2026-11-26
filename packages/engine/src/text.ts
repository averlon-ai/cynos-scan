/**
 * `text` without the copies of `char` it ends with. A loop, not a regex like `/\/+$/`: a regex
 * tries a match at every copy of `char`, and each scans the rest of the run, so a long run that
 * does not end the text takes quadratic time on Node (3.4 s at 100,000 slashes). CodeQL reports it
 * on input the caller doesn't control (js/polynomial-redos), and lint's
 * `regexp/no-super-linear-move` everywhere. The CLI has the same helper (`packages/cli/src/text.ts`).
 */
export function withoutTrailing(text: string, char: string): string {
  let end = text.length;
  while (end > 0 && text[end - 1] === char) end--;
  return text.slice(0, end);
}
