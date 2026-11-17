/**
 * `cynos completion bash|zsh|fish`: shell completion, generated from the command tree.
 *
 * The scripts are static: the commands, subcommands and their long options as this version has
 * them, so completion never runs the CLI (and never waits on Node) while you type.
 */
import type { Command } from 'commander';
import { CLI_NAME } from '../context';
import { CliError } from '../exit-codes';
import { withExamples } from '../help';

export const SHELLS = ['bash', 'zsh', 'fish'] as const;

export function registerCompletion(program: Command): void {
  const command = program
    .command('completion')
    .description('Print a shell completion script (bash, zsh or fish).')
    .argument('<shell>', SHELLS.join(', '))
    .action((shell: string) => {
      process.stdout.write(completionScript(program, shell));
    });
  withExamples(command, [
    `${CLI_NAME} completion zsh > "\${fpath[1]}/_${CLI_NAME}"`,
    `${CLI_NAME} completion bash >> ~/.bashrc`,
    `${CLI_NAME} completion fish > ~/.config/fish/completions/${CLI_NAME}.fish`,
  ]);
}

/** The command tree: each command's path, its subcommands and its long options. */
export function completionTree(
  program: Command
): Map<string, { subcommands: string[]; options: string[] }> {
  const tree = new Map<string, { subcommands: string[]; options: string[] }>();
  const walk = (command: Command, path: string): void => {
    tree.set(path, {
      subcommands: command.commands.map(child => child.name()),
      options: command.options
        .map(option => option.long)
        .filter((long): long is string => Boolean(long)),
    });
    for (const child of command.commands)
      walk(child, path ? `${path} ${child.name()}` : child.name());
  };
  walk(program, '');
  return tree;
}

export function completionScript(program: Command, shell: string): string {
  const tree = completionTree(program);
  if (shell === 'bash') return bash(tree);
  if (shell === 'zsh') return zsh(tree);
  if (shell === 'fish') return fish(tree);
  throw new CliError('usage', `completion takes ${SHELLS.join(', ')}, not ${shell}`);
}

type Tree = ReturnType<typeof completionTree>;

/**
 * bash and zsh walk the words typed so far, keeping only those that extend a known command path
 * (`scans` then `scans list`, never a path argument like `.`), then offer that path's
 * subcommands and options; anything else falls back to file names.
 */
function bash(tree: Tree): string {
  const fn = `_${CLI_NAME.replace(/-/g, '_')}`;
  const known = [...tree.keys()]
    .filter(Boolean)
    .map(path => `"${path}"`)
    .join('|');
  const cases = [...tree]
    .map(
      ([path, node]) =>
        `    "${path}") words="${[...node.subcommands, ...node.options].join(' ')}" ;;`
    )
    .join('\n');
  return `# ${CLI_NAME} bash completion
${fn}() {
  local cur cmdpath="" next words i
  cur="\${COMP_WORDS[COMP_CWORD]}"
  for ((i = 1; i < COMP_CWORD; i++)); do
    next="\${cmdpath:+$cmdpath }\${COMP_WORDS[i]}"
    case "$next" in ${known}) cmdpath="$next" ;; esac
  done
  case "$cmdpath" in
${cases}
    *) words="" ;;
  esac
  COMPREPLY=($(compgen -W "$words" -- "$cur"))
}
complete -o default -F ${fn} ${CLI_NAME}
`;
}

function zsh(tree: Tree): string {
  const fn = `_${CLI_NAME.replace(/-/g, '_')}`;
  const known = [...tree.keys()]
    .filter(Boolean)
    .map(path => `"${path}"`)
    .join('|');
  const cases = [...tree]
    .map(
      ([path, node]) =>
        `    "${path}") candidates=(${[...node.subcommands, ...node.options].map(word => `'${word}'`).join(' ')}) ;;`
    )
    .join('\n');
  return `#compdef ${CLI_NAME}
# ${CLI_NAME} zsh completion
${fn}() {
  local -a candidates
  local cmdpath="" next word
  for word in "\${(@)words[2,CURRENT-1]}"; do
    next="\${cmdpath:+$cmdpath }$word"
    case "$next" in ${known}) cmdpath="$next" ;; esac
  done
  case "$cmdpath" in
${cases}
  esac
  compadd -a candidates
  [[ -n "$cmdpath" && "$PREFIX" != -* ]] && _files
}
if [[ "\${zsh_eval_context[-1]}" == loadautofunc ]]; then ${fn} "$@"; else compdef ${fn} ${CLI_NAME}; fi
`;
}

function fish(tree: Tree): string {
  const lines = [`# ${CLI_NAME} fish completion`, `complete -c ${CLI_NAME} -f`];
  for (const [path, node] of tree) {
    const parts = path ? path.split(' ') : [];
    const condition = parts.length
      ? `__fish_seen_subcommand_from ${parts[parts.length - 1]}`
      : '__fish_use_subcommand';
    for (const sub of node.subcommands)
      lines.push(`complete -c ${CLI_NAME} -n '${condition}' -a ${sub}`);
    for (const option of node.options)
      lines.push(`complete -c ${CLI_NAME} -n '${condition}' -l ${option.replace(/^--/, '')}`);
  }
  return `${lines.join('\n')}\n`;
}
