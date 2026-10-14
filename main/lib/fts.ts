/**
 * Local full-text search over the turn store. An in-memory inverted index,
 * rebuilt from the on-disk store at boot and extended incrementally as turns
 * arrive — the STORE is the on-disk artifact, the index is derived state.
 * At the scale of one person's transcripts (tens of thousands of turns) a
 * rebuild is milliseconds, which buys us zero native dependencies.
 *
 * Query semantics: every term must match (AND); the final term matches as a
 * prefix, so search-as-you-type works. Ranking is left to the caller, which
 * orders hits by recency — relevance scoring on conversational text mostly
 * re-derives recency anyway.
 */

const TERM_MIN_LENGTH = 2;
const MAX_TERMS_PER_DOC = 512;

export function tokenize(text: string): string[] {
  return (text.toLowerCase().match(/[a-z0-9_]+/g) ?? []).filter(
    (t) => t.length >= TERM_MIN_LENGTH,
  );
}

export interface SearchIndex {
  /** term → doc ids containing it. */
  terms: Map<string, Set<string>>;
  docs: Set<string>;
}

export function createIndex(): SearchIndex {
  return { terms: new Map(), docs: new Set() };
}

export function indexDocument(index: SearchIndex, id: string, text: string): void {
  if (index.docs.has(id)) return;
  index.docs.add(id);
  const seen = new Set<string>();
  for (const term of tokenize(text)) {
    if (seen.size >= MAX_TERMS_PER_DOC) break;
    if (seen.has(term)) continue;
    seen.add(term);
    let ids = index.terms.get(term);
    if (!ids) {
      ids = new Set();
      index.terms.set(term, ids);
    }
    ids.add(id);
  }
}

/** Doc ids matching every query term (last term as prefix). Empty query → none. */
export function searchIndex(index: SearchIndex, query: string): Set<string> {
  const terms = tokenize(query);
  if (terms.length === 0) return new Set();
  const last = terms[terms.length - 1]!;
  const exact = terms.slice(0, -1);

  let candidates: Set<string> | undefined;
  for (const term of exact) {
    const ids = index.terms.get(term);
    if (!ids || ids.size === 0) return new Set();
    candidates = candidates ? intersect(candidates, ids) : new Set(ids);
    if (candidates.size === 0) return new Set();
  }

  // Prefix expansion for the trailing term: union of every indexed term that
  // starts with it. A linear scan of the vocabulary is fine at this scale.
  const prefixHits = new Set<string>();
  for (const [term, ids] of index.terms) {
    if (!term.startsWith(last)) continue;
    for (const id of ids) {
      if (!candidates || candidates.has(id)) prefixHits.add(id);
    }
  }
  return prefixHits;
}

function intersect(a: Set<string>, b: Set<string>): Set<string> {
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  const out = new Set<string>();
  for (const id of small) if (large.has(id)) out.add(id);
  return out;
}
