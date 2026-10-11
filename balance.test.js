const test = require('node:test');
const assert = require('node:assert/strict');
const { calculateBalanceAudit } = require('./balance');

const members = [
  { _id: 'payer', username: 'Payer' },
  { _id: 'one', username: 'One' },
  { _id: 'two', username: 'Two' },
  { _id: 'three', username: 'Three' }
];

const expense = (overrides = {}) => ({
  amount: 100,
  paidBy: { _id: 'payer', username: 'Payer' },
  splitBetween: ['one', 'two', 'three'],
  ...overrides
});

test('splits 100 rupees across three people with exact cent allocation', () => {
  const audit = calculateBalanceAudit({ expenses: [expense()], groupMembers: members });
  const shares = audit.members.filter((member) => ['one', 'two', 'three'].includes(member.id));
  assert.deepEqual(shares.map((member) => member.totalShare), [33.34, 33.33, 33.33]);
  assert.equal(shares.reduce((sum, member) => sum + member.totalShare, 0), 100);
  assert.equal(audit.sumOfNets, 0);
});

test('single-person split creates a debt when another person paid', () => {
  const audit = calculateBalanceAudit({
    expenses: [expense({ amount: 75, paidBy: { _id: 'payer', username: 'Payer' }, splitBetween: ['one'] })],
    groupMembers: members
  });
  assert.equal(audit.members.find((member) => member.id === 'one').net, -75);
  assert.deepEqual(audit.settlements, [{ from: 'One', to: 'Payer', amount: 75 }]);
});

test('personal expense nets to zero when payer is the only participant', () => {
  const audit = calculateBalanceAudit({
    expenses: [expense({ amount: 50, paidBy: { _id: 'one', username: 'One' }, splitBetween: ['one'] })],
    groupMembers: members
  });
  assert.equal(audit.members.find((member) => member.id === 'one').net, 0);
  assert.deepEqual(audit.settlements, []);
});

test('legacy empty split falls back to group members and nets to zero', () => {
  const audit = calculateBalanceAudit({ expenses: [expense({ splitBetween: [] })], groupMembers: members });
  assert.equal(audit.members.find((member) => member.id === 'one').totalShare, 25);
  assert.equal(audit.sumOfNets, 0);
});

test('keeps removed split members in the balance and balances nets to zero', () => {
  const audit = calculateBalanceAudit({
    expenses: [expense({ splitBetween: ['one', 'former-member'] })],
    groupMembers: members
  });
  assert.equal(audit.members.find((member) => member.id === 'former-member').totalShare, 50);
  assert.equal(audit.sumOfNets, 0);
});