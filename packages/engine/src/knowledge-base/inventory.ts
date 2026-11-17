/**
 * The repository's files, each with its kind, and the repository map built from them.
 *
 * Every agent in a scan otherwise starts by rediscovering the same facts: which files exist,
 * which are product code and which are vendored, minified, generated, tests or data. All of it
 * is computed once, before the scan, from the files alone:
 *
 *   kinds      code, template, config (product files a packet reviews), test, data, docs,
 *              other (stylesheets and repository metadata), and skip (vendored, minified,
 *              generated, lock and binary files)
 *   map        repo-map.md: a summary by kind, the files to skip with the reason, dependency
 *              manifests, every product file, and the other files counted per directory
 *
 * The map states facts only; it never says where a vulnerability is. The files are the ones git
 * would commit, so git-ignored files never reach a scan, and symbolic links are not followed: a
 * link must not pull a file from outside the checkout into a scan.
 *
 * Code is what is left: a readable file no rule below sets aside is product code. The rules name
 * the files with no product behaviour (documentation, data, stylesheets, repository metadata), not
 * the languages, because a missed file costs more than a needless one: a list of code extensions
 * left a Terraform or shell repository with almost no product files, and a file no packet reviews
 * is a finding no scan reports, while an extra one costs only the time to read it.
 */
import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { basename, extname, join } from 'node:path';

const TEMPLATE_EXT = new Set(
  '.html .htm .hbs .ejs .pug .jinja .jinja2 .j2 .tpl .twig .erb .mako .tmpl .mustache .njk .liquid .vm .ftl .jsp'.split(
    ' '
  )
);
const CONFIG_EXT = new Set(
  '.json .yml .yaml .toml .ini .cfg .conf .env .xml .properties'.split(' ')
);
/**
 * Documentation: by extension, or a project file's conventional name (LICENSE, LICENSE-MIT,
 * NOTICE.txt). Other .txt files are not set aside: CMakeLists.txt, robots.txt and requirements
 * files are product files.
 */
const DOC_EXT = new Set('.md .markdown .rst .adoc .asciidoc .org .rtf'.split(' '));
const DOC_NAME =
  /^(readme|license|licence|copying|notice|authors|contributors|changelog|changes|history|codeowners)(-[a-z0-9]+)?$/i;
/** Records rather than behaviour, whatever their size. */
const DATA_EXT = new Set('.csv .tsv .log .jsonl .ndjson'.split(' '));
/** Readable, but with no product behaviour: stylesheets and repository or tool metadata. */
const OTHER_EXT = new Set('.css .scss .sass .less .styl .patch .diff'.split(' '));
const OTHER_NAMES = new Set(
  [
    '.gitignore .gitattributes .gitmodules .gitkeep .keep .mailmap .editorconfig .dockerignore',
    '.npmignore .eslintignore .prettierignore .nvmrc .node-version .python-version .ruby-version',
    '.tool-versions',
  ]
    .join(' ')
    .split(' ')
);
const BINARY_EXT = new Set(
  '.png .jpg .jpeg .gif .ico .svg .webp .woff .woff2 .ttf .eot .pdf .zip .gz .tar .mp4 .mp3 .wasm .pyc .class .jar .so .dylib'.split(
    ' '
  )
);
const SKIP_DIRS = new Set(
  'node_modules vendor third_party dist build .next coverage __pycache__ .git bower_components target .venv venv'.split(
    ' '
  )
);
/** Trees with no product behaviour: tests exercise it, data trees only describe it. */
const TEST_DIRS = new Set(
  'test tests __tests__ spec specs cypress e2e testdata fixtures'.split(' ')
);
const DATA_DIRS = new Set(['i18n', 'locales', 'locale', 'translations', 'lang']);
/** A config, data or SQL file longer than this is a dump (i18n, seed data, schema). */
const DATA_MAX_LINES = 1000;
const LOCK_FILES = new Set(
  'package-lock.json yarn.lock pnpm-lock.yaml poetry.lock Pipfile.lock go.sum Cargo.lock composer.lock Gemfile.lock .terraform.lock.hcl'.split(
    ' '
  )
);
export const MANIFESTS = new Set(
  'package.json requirements.txt pyproject.toml setup.py Pipfile go.mod Cargo.toml pom.xml build.gradle composer.json Gemfile'.split(
    ' '
  )
);
/** A big script in a static-asset directory is almost always a library copied into the repository. */
const ASSET_DIRS = new Set(['static', 'assets', 'public', 'lib', 'libs', 'js', 'vendor']);
const VENDORED_MIN_LINES = 3000;
/** Bytes; a larger file is listed with its first MAX_READ bytes only. */
const MAX_READ = 2_000_000;
/** The kinds a packet and the baseline review line by line. */
export const PRODUCT_KINDS = new Set(['code', 'template', 'config']);

export interface FileRow {
  /** Repository-relative, with forward slashes. */
  path: string;
  lines: number;
  kind: string;
  /** Why a skipped file is skipped. */
  reason: string;
  /** The text, for every file but a skipped one. */
  text: string | undefined;
}

/** (kind, reason) for one file; kind 'skip' means agents need not read it. */
export function classify(path: string, text: string | undefined): [string, string] {
  const parts = path.split('/');
  const dirs = new Set(parts.slice(0, -1));
  const name = basename(path);
  const ext = extname(name).toLowerCase();
  const hit = (set: Set<string>): string | undefined => [...dirs].filter(d => set.has(d)).sort()[0];
  const lineCount = (text?.match(/\n/g) ?? []).length;
  const skipDir = hit(SKIP_DIRS);
  if (skipDir) return ['skip', `in ${skipDir}/`];
  if (BINARY_EXT.has(ext) || text === undefined) return ['skip', 'binary or unreadable'];
  if (LOCK_FILES.has(name) || ext === '.lock') return ['skip', 'lock file'];
  if (name.includes('.min.') || text.split('\n').some(line => line.length > 2000))
    return ['skip', 'minified or single very long line'];
  if (['.js', '.mjs', '.css'].includes(ext) && hit(ASSET_DIRS) && lineCount >= VENDORED_MIN_LINES)
    return ['skip', 'large script in an asset directory, likely a vendored library'];
  if (/(_pb2\.py|\.pb\.go|_gen\.go|\.generated\.)/.test(name)) return ['skip', 'generated'];
  if (hit(TEST_DIRS) || /(\.spec\.|\.test\.|_test\.)/.test(name)) return ['test', ''];
  if (
    hit(DATA_DIRS) ||
    DATA_EXT.has(ext) ||
    ((CONFIG_EXT.has(ext) || ['.txt', '.sql'].includes(ext)) &&
      !MANIFESTS.has(name) &&
      lineCount >= DATA_MAX_LINES)
  )
    return ['data', ''];
  if (TEMPLATE_EXT.has(ext)) return ['template', ''];
  if (CONFIG_EXT.has(ext) || MANIFESTS.has(name) || name.startsWith('.env')) return ['config', ''];
  if (DOC_EXT.has(ext) || DOC_NAME.test(ext === '.txt' ? name.slice(0, -4) : name))
    return ['docs', ''];
  if (OTHER_EXT.has(ext) || OTHER_NAMES.has(name)) return ['other', ''];
  // Nothing set it aside: any language, script, infrastructure as code or interface definition.
  return ['code', ''];
}

/**
 * The checkout's files as git lists them (tracked, and untracked but not ignored), relative to
 * root. A scan's checkout is a git work tree (preflight checks it), so a root git cannot list is
 * an error, never a reason to fall back to the directory's every file.
 */
function checkoutFiles(root: string): string[] {
  const listed = spawnSync(
    'git',
    ['-C', root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
    { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 }
  );
  if (listed.status !== 0)
    throw new Error(`git cannot list the files of ${root}: ${(listed.stderr ?? '').trim()}`);
  // A tracked file deleted from the work tree is listed but absent, and a submodule is listed as
  // a directory. Only regular files stay.
  const regular = (path: string): boolean => {
    try {
      return lstatSync(join(root, path)).isFile();
    } catch {
      return false;
    }
  };
  // A symbolic link is not followed: a link must not pull a file from outside the checkout into a
  // scan. lstat sees a link only in a path's last component, and git still lists a tracked path
  // under a directory a dirty checkout replaced with a link (src/ -> /elsewhere, src/config.py),
  // so a file stays only where its real path is its path in the checkout.
  const realRoot = realpathSync(root);
  const unlinked = (path: string): boolean => {
    try {
      return realpathSync(join(root, path)) === join(realRoot, path);
    } catch {
      return false;
    }
  };
  return [...new Set(listed.stdout.split('\0').filter(Boolean))]
    .filter(path => regular(path) && unlinked(path))
    .sort();
}

/** File text, or undefined for a binary; only the first MAX_READ bytes are kept. */
function readText(path: string): string | undefined {
  let data: Buffer;
  try {
    data = readFileSync(path).subarray(0, MAX_READ);
  } catch {
    return undefined;
  }
  if (data.subarray(0, 8192).includes(0)) return undefined;
  return data.toString('utf8');
}

/**
 * One row per regular file of the checkout at root, sorted by path.
 *
 * The files are the ones git would commit: tracked, plus untracked files no ignore rule covers.
 * A developer's checkout holds git-ignored files a repository never shares (`.env`,
 * `terraform.tfstate`, local keys), and every file listed here reaches the model through the
 * packets, the baseline and the architecture review, so an ignored file must never be listed.
 */
export function inventory(root: string): FileRow[] {
  return checkoutFiles(root).map(path => {
    const text = readText(join(root, path));
    const [kind, reason] = classify(path, text);
    return {
      path,
      lines: text ? (text.match(/\n/g) ?? []).length + 1 : 0,
      kind,
      reason,
      text: kind === 'skip' ? undefined : text,
    };
  });
}

/** The repository map, largest sections last so the summary reads first. */
export function repositoryMap(rows: FileRow[]): string {
  const count = (kind: string): number => rows.filter(r => r.kind === kind).length;
  const linesOf = (kind: string): number =>
    rows.filter(r => r.kind === kind).reduce((sum, r) => sum + r.lines, 0);
  const kinds = [...new Set(rows.map(r => r.kind))].sort();
  const top = new Map<string, number>();
  for (const r of rows.filter(r => r.kind === 'code')) {
    const d = r.path.includes('/') ? (r.path.split('/')[0] as string) : '.';
    top.set(d, (top.get(d) ?? 0) + 1);
  }
  const others = new Map<string, { files: number; lines: number; kinds: Set<string> }>();
  for (const r of rows) {
    if (['code', 'template', 'config', 'skip'].includes(r.kind)) continue;
    const parts = r.path.split('/');
    const d =
      parts.length > 2
        ? parts.slice(0, 2).join('/')
        : parts.length > 1
          ? (parts[0] as string)
          : '.';
    const e = others.get(d) ?? { files: 0, lines: 0, kinds: new Set<string>() };
    e.files += 1;
    e.lines += r.lines;
    e.kinds.add(r.kind);
    others.set(d, e);
  }
  return [
    '# Repository map',
    '',
    'Computed before the scan from the files alone. It lists facts (what each file is); it does',
    'not say where any vulnerability is. Use it to plan the review and to split files between',
    'helpers, and do not spend turns rediscovering what it already lists.',
    '',
    '## Summary',
    '',
    '| kind | files | lines |',
    '|---|---|---|',
    ...kinds.map(k => `| ${k} | ${count(k)} | ${linesOf(k)} |`),
    '',
    'Code files by top-level directory: ' +
      [...top]
        .sort((a, b) => b[1] - a[1])
        .map(([d, n]) => `\`${d}\` ${n}`)
        .join(', '),
    '',
    '## Files agents can skip',
    '',
    'Vendored, minified, generated, lock and binary files. Read one only if a finding depends',
    'on it.',
    '',
    ...rows
      .filter(r => r.kind === 'skip')
      .slice(0, 400)
      .map(r => `- \`${r.path}\`: ${r.reason}`),
    '',
    '## Dependency manifests',
    '',
    ...rows.filter(r => MANIFESTS.has(basename(r.path))).map(r => `- \`${r.path}\``),
    '',
    '## All product files',
    '',
    'Code, templates and configuration. Test trees, data files (i18n, seeds, dumps),',
    'documentation and other files are counted per directory below instead of listed.',
    '',
    '| path | kind | lines |',
    '|---|---|---|',
    ...rows
      .filter(r => PRODUCT_KINDS.has(r.kind))
      .map(r => `| \`${r.path}\` | ${r.kind} | ${r.lines} |`),
    '',
    '## Other files, by directory',
    '',
    ...[...others]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(
        ([d, e]) =>
          `- \`${d}/\`: ${e.files} files, ${e.lines} lines (${[...e.kinds].sort().join(', ')})`
      ),
    '',
  ].join('\n');
}
