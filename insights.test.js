const test = require('node:test');
const assert = require('node:assert/strict');
const { buildDailyInsights, buildInsightsSummary, getKolkataDateKey } = require('./insights');

const userId = 'me';
const members = [
  { _id: 'me', username: 'Me' },
  { _id: 'rahul', username: 'Rahul' },
  { _id: 'amit', username: 'Amit' },
  { _id: 'virendra', username: 'Virendra' }
];

const makeExpense = (overrides = {}) => ({
  _id: 'expense-1',
  description: 'Milk',
  amount: 300,
  category: 'Grocery',
  date: '2026-10-11T04:00:00.000Z',
  createdAt: '2026-10-11T04:00:00.000Z',
  paidBy: { _id: 'me', username: 'Me' },
  splitBetween: ['me'],
  ...overrides
});

const build = (expenses) => buildDailyInsights({
  expenses,
  groupMembers: members,
  userId,
  from: '2026-10-11',
  to: '2026-10-12'
});

test('counts personal expenses in full, including when paid by someone else', () => {
  const [today] = build([
    makeExpense(),
    makeExpense({ _id: 'roommate-paid', description: 'Egg tray', paidBy: { _id: 'rahul', username: 'Rahul' } })
  ]);
  assert.equal(today.total, 600);
  const roommatePaidItem = today.items.find((item) => item.description === 'Egg tray');
  assert.equal(roommatePaidItem.splitType, 'only_me');
  assert.equal(roommatePaidItem.label, 'Egg tray ₹300: Rahul paid, for you only');
});

test('calculates shared shares and gives remainder paise to first participant', () => {
  const [today] = build([
    makeExpense({ amount: 100, splitBetween: ['me', 'rahul', 'amit'] })
  ]);
  assert.equal(today.total, 33.34);
  assert.equal(today.items[0].splitType, 'shared');
  assert.equal(today.items[0].myShare, 33.34);
});

test('marks all-member splits and excludes expenses where the user is absent', () => {
  const [today, tomorrow] = build([
    makeExpense({ amount: 60, splitBetween: ['me', 'rahul', 'amit', 'virendra'] }),
    makeExpense({ _id: 'not-in-split', amount: 900, splitBetween: ['rahul', 'amit'] }),
    makeExpense({ _id: 'tomorrow', date: '2026-10-11T18:30:00.000Z', createdAt: '2026-10-11T18:30:00.000Z' })
  ]);
  assert.equal(today.total, 15);
  assert.equal(today.items[0].splitType, 'all');
  assert.equal(tomorrow.total, 300);
  assert.equal(getKolkataDateKey('2026-10-11T18:29:59.999Z'), '2026-10-11');
  assert.equal(getKolkataDateKey('2026-10-11T18:30:00.000Z'), '2026-10-12');
});

test('returns zero-total days for dates without expenses', () => {
  const [, tomorrow] = build([makeExpense()]);
  assert.equal(tomorrow.total, 0);
  assert.deepEqual(tomorrow.items, []);
});

test('groups month and week summaries and compares the previous period', () => {
  const daily = [
    { date: '2026-10-05', total: 100, items: [] },
    { date: '2026-10-06', total: 200, items: [] },
    { date: '2026-10-12', total: 50, items: [] }
  ];
  const previousDaily = [{ date: '2026-10-01', total: 100, items: [] }];

  const monthly = buildInsightsSummary({ daily, previousDaily, period: 'month' });
  assert.equal(monthly.buckets.length, 1);
  assert.equal(monthly.buckets[0].label, 'October 2026');
  assert.equal(monthly.total, 350);
  assert.equal(monthly.comparison.changePercent, 250);

  const weekly = buildInsightsSummary({ daily, previousDaily: [], period: 'week' });
  assert.deepEqual(weekly.buckets.map((bucket) => bucket.label), ['5 Oct–11 Oct', '12 Oct–18 Oct']);
});