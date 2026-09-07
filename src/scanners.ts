/**
 * Pure line-based PHP security scanners -- no `vscode` dependency.
 * Each function is a faithful port of one Gap Hunter Labs IntelliJ-
 * family plugin's Kotlin scanner (php-sql-injection-companion,
 * php-function-injection-companion, php-open-redirect-companion,
 * php-file-inclusion-companion, php-shell-injection-companion), all
 * of which were already plain-text/regex scanners with zero PSI
 * dependency -- ported here verbatim in spirit, translated to
 * TypeScript. Same evidence, same v0.1 scope limitations documented
 * in each function's comment as in the originals: plain-text
 * matching, not real PHP parsing, so a value that flows through an
 * intermediate variable isn't traced (real data-flow analysis, out
 * of scope for a text scanner).
 */

export interface Hit {
  rule: string;
  line: number; // 1-based
  startCol: number; // 0-based
  endCol: number; // 0-based, exclusive
  message: string;
}

function isCommentLine(trimmed: string): boolean {
  return trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*');
}

/** SQL injection: mysqli_query(/->query(/->exec( with an interpolated
 * or concatenated $variable instead of a prepared-statement
 * placeholder. */
export function scanSqlInjection(text: string): Hit[] {
  const QUERY_METHOD = /\b(mysqli_query|->\s*query|->\s*exec)\s*\(/;
  const INTERPOLATED_ARG = /"(?:[^"\\]|\\.)*\$\w/;
  const CONCAT_ARG = /(["'])(?:[^"'\\]|\\.)*\1\s*\.\s*\$\w/;

  const hits: Hit[] = [];
  text.split('\n').forEach((rawLine, index) => {
    const trimmed = rawLine.trimStart();
    if (isCommentLine(trimmed)) return;

    const callMatch = QUERY_METHOD.exec(rawLine);
    if (!callMatch) return;
    const afterCall = rawLine.slice(callMatch.index + callMatch[0].length);
    if (!INTERPOLATED_ARG.test(afterCall) && !CONCAT_ARG.test(afterCall)) return;

    const callName = callMatch[1].replace(/\s/g, '');
    hits.push({
      rule: 'sql-injection',
      line: index + 1,
      startCol: callMatch.index,
      endCol: callMatch.index + callMatch[0].length,
      message: `Potential SQL injection: '${callName}(' built with string interpolation/concatenation instead of a prepared-statement placeholder.`,
    });
  });
  return hits;
}

/** Function injection: call_user_func(/call_user_func_array( with a
 * callable name taken directly from a PHP superglobal. */
export function scanFunctionInjection(text: string): Hit[] {
  const DANGEROUS_CALL = /\b(call_user_func_array|call_user_func)\s*\(/;
  const SUPERGLOBAL = /\$_(GET|POST|REQUEST|COOKIE)\b/;

  const hits: Hit[] = [];
  text.split('\n').forEach((rawLine, index) => {
    const trimmed = rawLine.trimStart();
    if (isCommentLine(trimmed)) return;

    const callMatch = DANGEROUS_CALL.exec(rawLine);
    if (!callMatch) return;
    const afterCall = rawLine.slice(callMatch.index + callMatch[0].length);
    if (!SUPERGLOBAL.test(afterCall)) return;

    hits.push({
      rule: 'function-injection',
      line: index + 1,
      startCol: callMatch.index,
      endCol: callMatch.index + callMatch[0].length,
      message: `Potential function injection: '${callMatch[1]}(' called with a function name taken directly from a superglobal.`,
    });
  });
  return hits;
}

/** Open redirect: header(...) with a Location: value built directly
 * from a PHP superglobal. */
export function scanOpenRedirect(text: string): Hit[] {
  const HEADER_CALL = /\bheader\s*\(/;
  const LOCATION_HEADER = /Location\s*:/i;
  const SUPERGLOBAL = /\$_(GET|POST|REQUEST|COOKIE)\b/;

  const hits: Hit[] = [];
  text.split('\n').forEach((rawLine, index) => {
    const trimmed = rawLine.trimStart();
    if (isCommentLine(trimmed)) return;

    const callMatch = HEADER_CALL.exec(rawLine);
    if (!callMatch) return;
    const afterCall = rawLine.slice(callMatch.index + callMatch[0].length);
    if (!LOCATION_HEADER.test(afterCall) || !SUPERGLOBAL.test(afterCall)) return;

    hits.push({
      rule: 'open-redirect',
      line: index + 1,
      startCol: callMatch.index,
      endCol: callMatch.index + callMatch[0].length,
      message: "Potential open redirect: 'header(' sets a Location: value taken directly from a superglobal.",
    });
  });
  return hits;
}

/** File inclusion: include/include_once/require/require_once with a
 * path taken directly from a PHP superglobal (LFI/RFI). */
export function scanFileInclusion(text: string): Hit[] {
  const INCLUDE_CALL = /\b(include_once|require_once|include|require)\b/;
  const SUPERGLOBAL = /\$_(GET|POST|REQUEST|COOKIE)\b/;

  const hits: Hit[] = [];
  text.split('\n').forEach((rawLine, index) => {
    const trimmed = rawLine.trimStart();
    if (isCommentLine(trimmed)) return;

    const callMatch = INCLUDE_CALL.exec(rawLine);
    if (!callMatch) return;
    const afterCall = rawLine.slice(callMatch.index + callMatch[0].length);
    if (!SUPERGLOBAL.test(afterCall)) return;

    hits.push({
      rule: 'file-inclusion',
      line: index + 1,
      startCol: callMatch.index,
      endCol: callMatch.index + callMatch[0].length,
      message: `Potential local/remote file inclusion: '${callMatch[1]}' path taken directly from a superglobal.`,
    });
  });
  return hits;
}

/** Shell injection: eval/exec/shell_exec/system/passthru/popen with
 * an interpolated or concatenated $variable argument. */
export function scanShellInjection(text: string): Hit[] {
  const DANGEROUS_CALL = /\b(eval|exec|shell_exec|system|passthru|popen)\s*\(\s*"(?:[^"\\]|\\.)*\$\w/;
  const CONCAT_CALL = /\b(eval|exec|shell_exec|system|passthru|popen)\s*\(\s*(["'])(?:[^"'\\]|\\.)*\2\s*\.\s*\$\w/;

  const hits: Hit[] = [];
  text.split('\n').forEach((rawLine, index) => {
    const trimmed = rawLine.trimStart();
    if (isCommentLine(trimmed)) return;

    const match = DANGEROUS_CALL.exec(rawLine) ?? CONCAT_CALL.exec(rawLine);
    if (!match) return;

    hits.push({
      rule: 'shell-injection',
      line: index + 1,
      startCol: match.index,
      endCol: match.index + match[0].length,
      message: `Potential shell injection: '${match[1]}(' built with string interpolation/concatenation.`,
    });
  });
  return hits;
}

export function scanAll(text: string): Hit[] {
  return [
    ...scanSqlInjection(text),
    ...scanFunctionInjection(text),
    ...scanOpenRedirect(text),
    ...scanFileInclusion(text),
    ...scanShellInjection(text),
  ];
}
