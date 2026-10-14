/** robots.txt parsing and matching (RFC 9309): longest match wins, Allow wins ties. */

interface Rule {
  allow: boolean;
  pattern: string;
  regex: RegExp;
}

interface Group {
  agents: string[];
  rules: Rule[];
}

export interface Robots {
  sitemaps: string[];
  groups: Group[];
  isAllowed(userAgent: string, pathAndQuery: string): boolean;
}

const MAX_LINES = 5_000;
const MAX_PATTERN = 500;

function compile(pattern: string): RegExp {
  const anchored = pattern.endsWith("$");
  const body = (anchored ? pattern.slice(0, -1) : pattern)
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${body}${anchored ? "$" : ""}`);
}

export function parseRobots(text: string): Robots {
  const groups: Group[] = [];
  const sitemaps: string[] = [];
  let current: Group | undefined;
  let lastWasAgent = false;

  for (const rawLine of text.split(/\r?\n/).slice(0, MAX_LINES)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    const index = line.indexOf(":");
    if (index < 0) continue;
    const field = line.slice(0, index).trim().toLowerCase();
    const value = line.slice(index + 1).trim();

    if (field === "user-agent") {
      if (!current || !lastWasAgent) {
        current = { agents: [], rules: [] };
        groups.push(current);
      }
      current.agents.push(value.toLowerCase());
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (field === "sitemap") {
      if (value) sitemaps.push(value);
    } else if ((field === "allow" || field === "disallow") && current && value.length <= MAX_PATTERN) {
      // An empty Disallow means "allow everything" and carries no restriction.
      if (value === "" && field === "disallow") continue;
      current.rules.push({ allow: field === "allow", pattern: value, regex: compile(value) });
    }
  }

  const select = (userAgent: string): Group[] => {
    const ua = userAgent.toLowerCase();
    let best = -1;
    let selected: Group[] = [];
    for (const group of groups) {
      for (const agent of group.agents) {
        if (agent === "*" || !ua.includes(agent)) continue;
        if (agent.length > best) {
          best = agent.length;
          selected = [group];
        } else if (agent.length === best) {
          selected.push(group);
        }
      }
    }
    return selected.length > 0 ? selected : groups.filter((group) => group.agents.includes("*"));
  };

  return {
    sitemaps,
    groups,
    isAllowed(userAgent, pathAndQuery) {
      let verdict: { allow: boolean; length: number } | undefined;
      for (const group of select(userAgent)) {
        for (const rule of group.rules) {
          if (!rule.regex.test(pathAndQuery)) continue;
          const length = rule.pattern.length;
          if (!verdict || length > verdict.length || (length === verdict.length && rule.allow)) {
            verdict = { allow: rule.allow, length };
          }
        }
      }
      return verdict?.allow ?? true;
    },
  };
}
