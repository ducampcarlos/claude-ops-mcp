/** Minimal, bounded HTML helpers. Not a parser: enough to read <title>, robots and canonical. */

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, entity: string) => {
    if (entity[0] === "#") {
      const code = entity[1]?.toLowerCase() === "x" ? parseInt(entity.slice(2), 16) : parseInt(entity.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    }
    return ENTITIES[entity.toLowerCase()] ?? match;
  });
}

/** Only look at the start of the document: <head> is always there, and it bounds the regex work. */
function head(html: string): string {
  return html.slice(0, 200_000);
}

export function extractTitle(html: string): string | undefined {
  const match = /<title[^>]*>([^<]{0,1000})<\/title>/i.exec(head(html));
  const title = match?.[1] ? decodeEntities(match[1]).replace(/\s+/g, " ").trim() : "";
  return title || undefined;
}

function metaContent(html: string, name: string): string | undefined {
  const tags = head(html).match(/<meta\s[^>]{0,500}>/gi) ?? [];
  for (const tag of tags) {
    const nameMatch = /\bname\s*=\s*["']?([^"'\s>]+)/i.exec(tag);
    if (nameMatch?.[1]?.toLowerCase() !== name) continue;
    const content = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    const value = content?.[1] ?? content?.[2] ?? content?.[3];
    if (value !== undefined) return decodeEntities(value).trim();
  }
  return undefined;
}

export function extractMetaRobots(html: string): string | undefined {
  return metaContent(html, "robots");
}

export function extractMetaDescription(html: string): string | undefined {
  return metaContent(html, "description");
}

export function extractCanonical(html: string): string | undefined {
  const links = head(html).match(/<link\s[^>]{0,500}>/gi) ?? [];
  for (const tag of links) {
    if (!/\brel\s*=\s*["']?canonical\b/i.test(tag)) continue;
    const href = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    const value = href?.[1] ?? href?.[2] ?? href?.[3];
    if (value) return decodeEntities(value).trim();
  }
  return undefined;
}

export function hasNoindex(robots: string | undefined): boolean {
  return !!robots && /(^|[\s,])(noindex|none)([\s,]|$)/i.test(robots);
}
