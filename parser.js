function splitExpenseEntries(text) {
  const source = String(text ?? '').trim();
  if (!source) return [];

  const entries = [];
  let current = '';

  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    const isSeparator = ch === ',' || ch === '\n';

    if (!isSeparator) {
      current += ch;
      continue;
    }

    const previous = current[current.length - 1] ?? '';
    const nextNonSpace = source.slice(i + 1).match(/\S/);
    const next = nextNonSpace ? nextNonSpace[0] : '';
    const previousIsDigit = /\d/.test(previous);
    const nextIsDigit = /\d/.test(next);

    if (ch === ',' && previousIsDigit && nextIsDigit) {
      current += ch;
      continue;
    }

    if (current.trim()) {
      entries.push(current.trim());
    }
    current = '';
  }

  if (current.trim()) {
    entries.push(current.trim());
  }

  return entries.filter(Boolean);
}

function parseCurrencyAmount(rawAmount) {
  if (rawAmount == null) return null;

  const cleaned = String(rawAmount)
    .replace(/₹/gi, '')
    .replace(/\bRs\b/gi, '')
    .replace(/\bR\b/gi, '')
    .replace(/,/g, '')
    .trim();

  if (!cleaned) return null;

  const value = Number(cleaned);
  if (!Number.isFinite(value) || value <= 0) return null;
  return value;
}

function parseExpenseEntry(entryText) {
  const entry = String(entryText ?? '').trim();
  if (!entry) return null;

  const tagMatches = Array.from(entry.matchAll(/@\S+/g));
  const tags = tagMatches.map((match) => match[0]);
  const rawTagText = tags.length ? entry.slice(0, tagMatches[tagMatches.length - 1].index + tagMatches[tagMatches.length - 1][0].length) : '';
  const textWithoutTags = entry.replace(new RegExp(`^${rawTagText.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*`, 'i'), '').trim();

  const amountMatch = textWithoutTags.match(/(?:₹|rs|Rs)?\s*[-+]?(?:(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?|\.\d+)\s*$/i);
  if (!amountMatch) return null;

  const amountText = amountMatch[0].trim();
  const description = textWithoutTags.slice(0, textWithoutTags.length - amountText.length).trim();
  const amount = parseCurrencyAmount(amountText);

  if (!description || amount == null) return null;

  return {
    tags,
    description,
    amount,
    raw: entry
  };
}

function parseExpenseText(rawText) {
  return splitExpenseEntries(rawText)
    .map((entry) => parseExpenseEntry(entry))
    .filter(Boolean);
}

function parseTelegramCommand(text) {
  const match = String(text ?? '').trim().match(/^\/([a-z0-9_]+)(?:@\w+)?(?:\s+([\s\S]*))?$/i);
  if (!match) return null;
  return { command: match[1].toLowerCase(), argumentText: (match[2] || '').trim() };
}

function normalizeTag(tag) {
  return String(tag || '').replace(/^@/, '').trim().toLowerCase();
}

function resolveSplitTags({ tags = [], sender, groupMembers = [] }) {
  if (!sender || !groupMembers.length) {
    return { ok: false, error: 'No group members available.' };
  }

  const senderId = String(sender._id || sender.id || sender);
  const memberLookup = groupMembers.map((member) => ({
    id: String(member._id || member.id),
    username: String(member.username || '').toLowerCase(),
    nickname: String(member.nickname || '').toLowerCase(),
    displayName: String(member.username || '').toLowerCase()
  }));

  const hasAllTag = tags.some((tag) => normalizeTag(tag) === 'all');
  if (hasAllTag) {
    return { ok: true, splitBetween: [...new Set(memberLookup.map((member) => member.id))], mode: 'all' };
  }

  if (!tags || tags.length === 0) {
    return { ok: true, splitBetween: [...new Set(memberLookup.map((member) => member.id))], mode: 'all' };
  }

  const resolvedIds = [];
  const seen = new Set();
  const errors = [];

  const addResolved = (memberId) => {
    if (!memberId) return;
    const key = String(memberId);
    if (!seen.has(key)) {
      seen.add(key);
      resolvedIds.push(key);
    }
  };

  for (const tag of tags) {
    const rawTag = String(tag || '').trim();
    const normalized = normalizeTag(rawTag);

    if (!normalized) continue;

    if (normalized === 'me' || normalized === String(sender.username || '').toLowerCase() || normalized === String(sender.nickname || '').toLowerCase()) {
      addResolved(senderId);
      continue;
    }

    const exactMatches = memberLookup.filter((member) => member.username === normalized || member.nickname === normalized);
    if (exactMatches.length > 0) {
      addResolved(exactMatches[0].id);
      continue;
    }

    const prefixMatches = memberLookup.filter((member) => member.username.startsWith(normalized) || member.nickname.startsWith(normalized));
    if (prefixMatches.length === 1) {
      addResolved(prefixMatches[0].id);
      continue;
    }

    if (prefixMatches.length > 1) {
      errors.push({ type: 'ambiguous', tag: rawTag, members: prefixMatches.map((member) => member.displayName) });
      continue;
    }

    errors.push({ type: 'unknown', tag: rawTag, members: memberLookup.map((member) => member.displayName) });
  }

  if (errors.length > 0) {
    return { ok: false, error: errors[0] };
  }

  return { ok: true, splitBetween: resolvedIds, mode: resolvedIds.includes(senderId) ? 'personal-or-mixed' : 'shared' };
}

module.exports = {
  splitExpenseEntries,
  parseExpenseEntry,
  parseExpenseText,
  parseTelegramCommand,
  resolveSplitTags,
  parseCurrencyAmount
};
