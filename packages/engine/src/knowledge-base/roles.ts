/**
 * The roles a file can play in an application's security architecture. The file sweep asks Jev
 * for each text file's role (plan.ts); the architecture review fills its core and builds its
 * checklist from them (architecture.ts, architecture-agent.ts).
 */
export const ARCHITECTURE_ROLES = [
  'startup',
  'routes',
  'access_control',
  'configuration',
  'deployment',
  'data_integrations',
  'architecture_docs',
] as const;
export type ArchitectureRole = (typeof ARCHITECTURE_ROLES)[number];
