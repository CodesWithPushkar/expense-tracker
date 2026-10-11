const getId = (value) => {
  if (value == null) return '';
  if (typeof value === 'object') return String(value._id || value.id || value);
  return String(value);
};

const getName = (member) => member.nickname || member.username || member.name || 'Unknown';

const calculateBalanceAudit = ({ expenses, groupMembers = [] }) => {
  const people = new Map();
  const paidCents = new Map();
  const shareCents = new Map();

  const addPerson = (idValue, member = {}) => {
    const id = getId(idValue);
    if (!id) return '';
    if (!people.has(id)) people.set(id, { id, username: getName(member) });
    else if (people.get(id).username === 'Unknown' && getName(member) !== 'Unknown') {
      people.get(id).username = getName(member);
    }
    if (!paidCents.has(id)) paidCents.set(id, 0);
    if (!shareCents.has(id)) shareCents.set(id, 0);
    return id;
  };

  groupMembers.forEach((member) => addPerson(member._id || member.id || member, member));

  for (const expense of expenses) {
    const amount = Number(expense.amount);
    if (!Number.isFinite(amount) || amount < 0) continue;
    const payerId = addPerson(expense.paidBy && (expense.paidBy._id || expense.paidBy.id || expense.paidBy), expense.paidBy || {});
    if (!payerId) continue;

    const explicitSplit = [...new Set((expense.splitBetween || []).map(getId).filter(Boolean))];
    const splitIds = explicitSplit.length
      ? explicitSplit
      : groupMembers.map((member) => addPerson(member._id || member.id || member, member)).filter(Boolean);
    const participants = splitIds.length ? splitIds : [payerId];
    const totalCents = Math.round(amount * 100);
    const baseShare = Math.floor(totalCents / participants.length);
    const extraCents = totalCents % participants.length;

    paidCents.set(payerId, paidCents.get(payerId) + totalCents);
    participants.forEach((id, index) => {
      addPerson(id);
      shareCents.set(id, shareCents.get(id) + baseShare + (index < extraCents ? 1 : 0));
    });
  }

  const netCents = new Map([...people.keys()].map((id) => [id, (paidCents.get(id) || 0) - (shareCents.get(id) || 0)]));
  const sumBeforeAdjustment = [...netCents.values()].reduce((sum, amount) => sum + amount, 0);
  if (sumBeforeAdjustment !== 0 && netCents.size > 0) {
    const largest = [...netCents.entries()].sort((left, right) => Math.abs(right[1]) - Math.abs(left[1]))[0];
    netCents.set(largest[0], largest[1] - sumBeforeAdjustment);
  }

  const members = [...people.values()].map((person) => ({
    ...person,
    totalPaid: (paidCents.get(person.id) || 0) / 100,
    totalShare: (shareCents.get(person.id) || 0) / 100,
    net: (netCents.get(person.id) || 0) / 100
  }));
  const nameById = new Map(members.map((member) => [member.id, member.username]));
  const debtors = [...netCents.entries()]
    .filter(([, amount]) => amount < 0)
    .map(([id, amount]) => ({ id, amount: -amount }))
    .sort((left, right) => right.amount - left.amount);
  const creditors = [...netCents.entries()]
    .filter(([, amount]) => amount > 0)
    .map(([id, amount]) => ({ id, amount }))
    .sort((left, right) => right.amount - left.amount);

  const settlements = [];
  let debtorIndex = 0;
  let creditorIndex = 0;
  while (debtorIndex < debtors.length && creditorIndex < creditors.length) {
    const debtor = debtors[debtorIndex];
    const creditor = creditors[creditorIndex];
    const cents = Math.min(debtor.amount, creditor.amount);
    settlements.push({
      from: nameById.get(debtor.id) || 'Unknown',
      to: nameById.get(creditor.id) || 'Unknown',
      amount: cents / 100
    });
    debtor.amount -= cents;
    creditor.amount -= cents;
    if (debtor.amount === 0) debtorIndex += 1;
    if (creditor.amount === 0) creditorIndex += 1;
  }

  return {
    members,
    settlements,
    sumOfNets: members.reduce((sum, member) => sum + Math.round(member.net * 100), 0) / 100
  };
};

module.exports = { calculateBalanceAudit, getId };