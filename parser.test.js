const test = require('node:test');
const assert = require('node:assert/strict');
const { splitExpenseEntries, parseExpenseEntry, parseExpenseText, resolveSplitTags } = require('./parser');

const members = [
  { _id: 'u1', username: 'rahul', nickname: 'R' },
  { _id: 'u2', username: 'amit', nickname: 'Amit' },
  { _id: 'u3', username: 'meera', nickname: 'Meera' },
  { _id: 'u4', username: 'allen', nickname: 'Allen' },
  { _id: 'u5', username: 'pushkar', nickname: 'Pushkar' }
];

const sender = { _id: 'u5', username: 'pushkar', nickname: 'Pushkar' };

test('split entries handles commas, whitespace and numbers', () => {
  const entries = splitExpenseEntries('@all milk 20, @r egg 30\n@amit dal 40');
  assert.deepEqual(entries, ['@all milk 20', '@r egg 30', '@amit dal 40']);
  assert.deepEqual(splitExpenseEntries('@all rent 1,200'), ['@all rent 1,200']);
  assert.deepEqual(splitExpenseEntries('@all rent 1,25,000'), ['@all rent 1,25,000']);
});

test('parseExpenseEntry extracts tags, description and amount', () => {
  const parsed = parseExpenseEntry('@rahul milk 20');
  assert.ok(parsed);
  assert.deepEqual(parsed.tags, ['@rahul']);
  assert.equal(parsed.description, 'milk');
  assert.equal(parsed.amount, 20);

  const parsedWithCurrency = parseExpenseEntry('@me @rahul lunch 120');
  assert.ok(parsedWithCurrency);
  assert.equal(parsedWithCurrency.amount, 120);
  assert.equal(parsedWithCurrency.description, 'lunch');
});

test('parseExpenseText handles multiple entries and rupee prefixes', () => {
  const parsed = parseExpenseText('@all green tea ₹50\n@r egg 30\n@me coffee 50.5');
  assert.equal(parsed.length, 3);
  assert.equal(parsed[0].description, 'green tea');
  assert.equal(parsed[1].amount, 30);
  assert.equal(parsed[2].amount, 50.5);
});

test('resolveSplitTags handles all, me, exact and prefix matches', () => {
  assert.deepEqual(resolveSplitTags({ tags: ['@all'], sender, groupMembers: members }).splitBetween.sort(), ['u1', 'u2', 'u3', 'u4', 'u5'].sort());
  assert.deepEqual(resolveSplitTags({ tags: ['@me'], sender, groupMembers: members }).splitBetween, ['u5']);
  assert.deepEqual(resolveSplitTags({ tags: ['@rahul'], sender, groupMembers: members }).splitBetween, ['u1']);
  assert.deepEqual(resolveSplitTags({ tags: ['@r'], sender, groupMembers: members }).splitBetween, ['u1']);
  assert.deepEqual(resolveSplitTags({ tags: ['@me', '@rahul'], sender, groupMembers: members }).splitBetween.sort(), ['u1', 'u5']);
  assert.equal(resolveSplitTags({ tags: ['@mee'], sender, groupMembers: members }).ok, true);
  assert.equal(resolveSplitTags({ tags: ['@allen'], sender, groupMembers: members }).ok, true);
});

test('ambiguous or unknown tags return errors', () => {
  const ambiguous = resolveSplitTags({ tags: ['@a'], sender, groupMembers: members });
  assert.equal(ambiguous.ok, false);
  assert.equal(ambiguous.error.type, 'ambiguous');

  const unknown = resolveSplitTags({ tags: ['@ghost'], sender, groupMembers: members });
  assert.equal(unknown.ok, false);
  assert.equal(unknown.error.type, 'unknown');
});

test('invalid entries reject malformed or zero values', () => {
  assert.equal(parseExpenseEntry('milk 0'), null);
  assert.equal(parseExpenseEntry('milk -20'), null);
  assert.equal(parseExpenseEntry('   '), null);
  assert.equal(parseExpenseEntry('@all 0'), null);
});
