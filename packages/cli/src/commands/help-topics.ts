/**
 * `cynos help <topic>`: the concepts a command's help has no room for.
 *
 * A command's --help lists its options; how the login, the runtimes, diff scans, the knowledge
 * base and the exit codes work spans several commands. `help <command>` still shows a command's
 * help, so one entry point answers both.
 */
import type { Command } from 'commander';
import { CLI_NAME } from '../context';
import { CliError } from '../exit-codes';
import { withExamples } from '../help';
import { ENVIRONMENT } from '../settings';

export const TOPICS: Record<string, { summary: string; text: () => string }> = {
  auth: {
    summary: 'the login, the endpoint, and where the key is kept',
    text: () => `The cynos key is the login, and the only key a scan needs.

  ${CLI_NAME} login                       prompt for the key (masked), check it, save it
  printf %s "$KEY" | ${CLI_NAME} login --with-api-key
  ${CLI_NAME} auth status [--json]        which key a scan uses, and from where
  ${CLI_NAME} logout                      remove the saved key

Lookup order: CYNOS_API_KEY, then the saved login. A key from the environment is read
once and removed from it, so no child process inherits it; it never goes in argv or in a log line.
The key is checked and used at https://api.cynos.averlon.ai/v1 unless CYNOS_BASE_URL names
another endpoint.

A saved key goes to the macOS keychain (security), the Secret Service on Linux (secret-tool), or a
0600 file in ~/.config/averlon/cynos/ when neither is available
(CYNOS_CREDENTIAL_STORE=file forces the file).`,
  },
  runtimes: {
    summary: 'native and docker: where upstream runs',
    text: () => `A scan runs upstream (@openai/codex-security, pinned) in one of two runtimes.

  native  (default)  upstream from node_modules on this machine, under Codex's own OS sandbox
                     (Seatbelt on macOS, Bubblewrap on Linux), exactly as \`cs\` runs it.
  docker             the hardened scanner container: seccomp and AppArmor profiles,
                     --cap-drop ALL, a read-only checkout, no network for the preflight.

Choose with --runtime, or CYNOS_SCAN_RUNTIME=docker. \`${CLI_NAME} doctor --runtime all\` checks
both; \`doctor --fix\` installs what a runtime is missing, upstream's AppArmor profile on Linux
included (asking before sudo).

Both runtimes keep each scan in a run dir, so \`${CLI_NAME} scans\` lists, shows and exports a
docker scan as it does a native one.

The docker runtime's containers belong to the Docker daemon, which resolves their bind mounts on
its own host. When cynos itself runs in a container and reaches the host's Docker through
its socket, its paths do not exist there: --host-path HERE=HOST (repeatable) gives each mount
source under HERE as the same path under HOST, e.g. --host-path /srv/out=/out.`,
  },
  'diff-scans': {
    summary: '--diff and --since-last-scan',
    text: () => `A diff scan reviews only the changes from a base revision to HEAD. Before it, the engine
builds a knowledge base for the change: the code graph at HEAD, the call paths through every
changed function (up to entry points, down to sensitive operations), the last full scan's
architecture review brought up to date when the change touches what it describes, and a brief
for each helper's part of the change. The helpers start at once, each from its brief.

A diff starts from the last full scan's threat model, kept in the knowledge-base cache (help
knowledge-base). With none stored for the repository, or one of a commit outside HEAD's history,
the diff first reviews the whole repository at HEAD, as a full scan does, and keeps that review
for the next diff: cached labels answer the files the change left alone, but the first such diff
takes as long as a full scan's knowledge base.

  ${CLI_NAME} scan . --diff origin/main     the changes since origin/main
  ${CLI_NAME} scan . --since-last-scan      the changes since this repository's last completed scan

--since-last-scan reads this machine's scans (\`scans list\`). It diffs only when that scan's
revision is an ancestor of HEAD; after a rebase or on another branch it runs a full scan and
says why. A diff needs a clean checkout at HEAD.`,
  },
  'knowledge-base': {
    summary: 'what a scan builds first, and its cache',
    text: () => `Before a full scan, the engine builds a knowledge base for the scan to plan around: a code
graph, Jev's labels, an architecture review, the review packets and a brief for each helper. A
diff builds one sized to the change (help diff-scans).
Every model call it makes goes through cynos with the cynos key, and Jev's spend stops at $10.

The cache (Jev's answers, the code graph, the stored architecture review) is kept between
scans as one snapshot per scanned commit in <state>/averlon/knowledge-base-cache/. A diff scan
restores its base commit's snapshot to start from that review and reuse Jev's answers, else the
newest snapshot of a commit in HEAD's history, else the newest. It saves one only when it built
its own threat model. \`${CLI_NAME} gc\` prunes old snapshots.`,
  },
  'scan-inputs': {
    summary: 'steering a scan: --rubric, --false-positives',
    text: () => `How a scan grades severity, and which findings reviewers already dismissed.

  --rubric FILE          grade severity with the rubric in FILE instead of upstream's default:
                         upstream's lead gets it as --rubric, and every helper prints it first
  --false-positives FILE findings your reviewers dismissed, as a JSON array:
                           [{"title": "Kubeconfig written world-readable",
                             "locations": [{"path": "job/scan.go", "startLine": 1083}],
                             "fingerprint": "codex-security/v1:sha256:...",
                             "reason": "Each scan job is a single-tenant pod."}]

A dismissal names its finding by its title and at least one location, as the scan's
findings.json has them, with its fingerprint (fingerprints.primary) when you have it, and needs a
reason of up to 2400 characters. The scan reads them as reviewer feedback, as upstream reads the
dismissals in its own history: it drops a finding only if the recorded reason still holds
against the current source, so a dismissal never hides a finding the code has changed under.`,
  },
  'exit-codes': {
    summary: "upstream's exit codes, which cynos keeps",
    text: () => `  0    completed, or passes the severity policy
  1    severity policy violation (--fail-on-severity)
  2    every failure: invalid input, login, host check, knowledge base, runtime error,
       target change, a scan upstream stopped short, required-output failure, a scan
       stopped by --timeout
  130  interrupted (Ctrl-C)
  143  terminated (SIGTERM)

What went wrong is on stderr, and in --format json as error.kind (usage, auth, budget, model,
network, gateway, host-check, knowledge-base, engine, upstream, interrupted, timed-out, internal).`,
  },
  env: {
    summary: 'environment variables',
    text: () => {
      const width = Math.max(...ENVIRONMENT.map(([name]) => name.length)) + 2;
      return ENVIRONMENT.map(([name, effect]) => `  ${name.padEnd(width)}${effect}`).join('\n');
    },
  },
};

export function registerHelpTopics(program: Command): void {
  program.addHelpCommand(false);
  const command = program
    .command('help')
    .description(
      'Help on a command or a topic: auth, runtimes, diff-scans, knowledge-base, scan-inputs, exit-codes, env.'
    )
    .argument('[topic...]', 'a topic, or a command (scan, scans list, …)')
    .action((words: string[]) => helpCommand(program, words));
  withExamples(command, [
    `${CLI_NAME} help auth`,
    `${CLI_NAME} help exit-codes`,
    `${CLI_NAME} help scan`,
  ]);
  program.addHelpText(
    'after',
    `\nTopics: ${Object.keys(TOPICS).join(', ')} (${CLI_NAME} help <topic>)\n`
  );
}

function helpCommand(program: Command, words: string[]): void {
  if (!words.length) return program.help();
  const topic = TOPICS[words.join(' ')];
  if (topic) {
    process.stdout.write(`${topic.text()}\n`);
    return;
  }
  // A command: walk its path, then show its own help.
  let command: Command | undefined = program;
  for (const word of words)
    command = command?.commands.find(
      child => child.name() === word || child.aliases().includes(word)
    );
  if (command && command !== program) return command.help();
  throw new CliError(
    'usage',
    `No help topic or command "${words.join(' ')}".`,
    `Topics: ${Object.keys(TOPICS).join(', ')}.`
  );
}
