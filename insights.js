const INDIA_TIME_ZONE = 'Asia/Kolkata';

const getId = (value) => {
  if (value == null) return '';
  if (typeof value === 'object') return String(value._id || value);
  return String(value);
};

const getKolkataDateKey = (value) => new Intl.DateTimeFormat('en-CA', {
  timeZone: INDIA_TIME_ZONE,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit'
}).format(new Date(value));

const isDateKey = (value) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return date.toISOString().slice(0, 10) === value;
};

const addDays = (dateKey, count) => {
  const date = new Date(`${dateKey}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() + count);
  return date.toISOString().slice(0, 10);
};

const dateKeyToUtcStart = (dateKey) => new Date(`${dateKey}T00:00:00.000+05:30`);

const getInclusiveDayCount = (from, to) => {
  const start = new Date(`${from}T00:00:00.000Z`);
  const end = new Date(`${to}T00:00:00.000Z`);
  return Math.floor((end - start) / 86400000) + 1;
};

const formatRupees = (amount) => `₹${new Intl.NumberFormat('en-IN', {
  maximumFractionDigits: 2,
  minimumFractionDigits: Number.isInteger(amount) ? 0 : 2
}).format(amount)}`;

const getShareCents = (amount, participantIndex, participantCount) => {
  if (participantIndex < 0 || participantCount < 1) return 0;
  const totalCents = Math.round(Number(amount) * 100);
  const baseCents = Math.floor(totalCents / participantCount);
  const remainderCents = totalCents % participantCount;
  return baseCents + (participantIndex < remainderCents ? 1 : 0);
};

const getTimeInKolkata = (value) => new Intl.DateTimeFormat('en-IN', {
  timeZone: INDIA_TIME_ZONE,
  hour: 'numeric',
  minute: '2-digit',
  hour12: true
}).format(new Date(value));

const getDisplayName = (member) => member.nickname || member.username || 'Member';

const buildItemLabel = (item) => {
  const payerText = item.paidBy.isMe ? 'you paid' : `${item.paidBy.username} paid`;
  if (item.splitType === 'only_me') {
    return `${item.description} ${formatRupees(item.totalAmount)}: ${payerText}, for you only`;
  }
  if (item.splitType === 'all') {
    return `${item.description} ${formatRupees(item.totalAmount)}: your share ${formatRupees(item.myShare)} (split between all ${item.splitCount})`;
  }
  if (!item.myShare) {
    return `${item.description} ${formatRupees(item.totalAmount)}: you paid, not included in the split`;
  }
  return `${item.description} ${formatRupees(item.totalAmount)}: your share ${formatRupees(item.myShare)} (split with ${item.splitWith.join(', ')}; ${payerText})`;
};

const buildDailyInsights = ({ expenses, groupMembers, userId, from, to, mode = 'share' }) => {
  const groupIds = groupMembers.map((member) => getId(member._id)).filter(Boolean);
  const groupNames = new Map(groupMembers.map((member) => [getId(member._id), getDisplayName(member)]));
  const days = new Map();

  for (let cursor = from; cursor <= to; cursor = addDays(cursor, 1)) {
    days.set(cursor, { date: cursor, totalCents: 0, items: [] });
  }

  for (const expense of expenses) {
    const expenseDate = expense.date || expense.createdAt;
    if (!expenseDate) continue;
    const date = getKolkataDateKey(expenseDate);
    const day = days.get(date);
    if (!day) continue;

    const payer = expense.paidBy || {};
    const payerId = getId(payer);
    const splitIds = [...new Set((expense.splitBetween || []).map(getId).filter(Boolean))];
    const participants = splitIds.length ? splitIds : groupIds;
    const participantIndex = participants.indexOf(userId);
    const myShareCents = getShareCents(expense.amount, participantIndex, participants.length);
    const isPaidMode = mode === 'paid';
    if (isPaidMode ? payerId !== userId : participantIndex < 0) continue;

    const totalCents = Math.round(Number(expense.amount) * 100);
    const isOnlyMe = participants.length === 1 && participants[0] === userId;
    const isAll = groupIds.length > 0 && participants.length === groupIds.length
      && groupIds.every((id) => participants.includes(id));
    const splitType = isOnlyMe ? 'only_me' : isAll ? 'all' : 'shared';
    const splitWith = participants.filter((id) => id !== userId).map((id) => groupNames.get(id) || 'Member');
    const myShare = myShareCents / 100;
    const valueCents = isPaidMode ? totalCents : myShareCents;
    const item = {
      expenseId: getId(expense._id),
      description: expense.description || 'Expense',
      category: expense.category || 'General',
      time: getTimeInKolkata(expense.createdAt || expenseDate),
      totalAmount: totalCents / 100,
      myShare,
      value: valueCents / 100,
      paidBy: {
        id: payerId,
        username: payer.username || groupNames.get(payerId) || 'Unknown',
        isMe: payerId === userId
      },
      splitCount: participants.length,
      splitType,
      splitWith
    };
    item.label = buildItemLabel(item);
    day.totalCents += valueCents;
    day.items.push(item);
  }

  return [...days.values()].map((day) => {
    day.items.sort((left, right) => right.value - left.value || left.description.localeCompare(right.description));
    const total = day.totalCents / 100;
    const today = getKolkataDateKey(new Date());
    const dateDescription = day.date === today ? 'today' : day.date;
    const topItems = day.items.slice(0, 3).map((item) => {
      if (mode === 'paid') return `${item.description} ${formatRupees(item.totalAmount)} (you paid)`;
      if (item.splitType === 'only_me') {
        const payer = item.paidBy.isMe ? 'you paid' : `${item.paidBy.username} paid`;
        return `${formatRupees(item.totalAmount)} ${item.description} (${payer}, for you only)`;
      }
      return `${formatRupees(item.myShare)} ${item.description}`;
    });
    const remainingCount = day.items.length - topItems.length;
    const details = topItems.length
      ? `: ${topItems.join(' + ')}${remainingCount > 0 ? ` + ${remainingCount} more` : ''}`
      : '';
    return {
      date: day.date,
      total,
      items: day.items,
      summary: `${formatRupees(total)} ${mode === 'paid' ? 'paid' : ''} ${dateDescription}${details}`.replace(/  +/g, ' ').trim()
    };
  });
};

const getWeekStart = (dateKey) => {
  const day = new Date(`${dateKey}T00:00:00.000Z`).getUTCDay();
  return addDays(dateKey, -(day === 0 ? 6 : day - 1));
};

const formatShortDate = (dateKey) => new Intl.DateTimeFormat('en-IN', {
  timeZone: 'UTC',
  day: 'numeric',
  month: 'short'
}).format(new Date(`${dateKey}T00:00:00.000Z`));

const buildInsightsSummary = ({ daily, previousDaily, period }) => {
  const totalCents = daily.reduce((sum, day) => sum + Math.round(day.total * 100), 0);
  const previousTotalCents = previousDaily.reduce((sum, day) => sum + Math.round(day.total * 100), 0);
  const daysCount = daily.length;
  const topDay = daily.reduce((best, day) => day.total > (best?.total || 0) ? day : best, null);
  const highestDay = topDay && topDay.total > 0 ? {
    date: topDay.date,
    amount: topDay.total,
    topItem: topDay.items[0] || null
  } : null;
  const categories = new Map();
  daily.forEach((day) => day.items.forEach((item) => {
    const cents = Math.round(item.value * 100);
    categories.set(item.category, (categories.get(item.category) || 0) + cents);
  }));
  const categoryBreakdown = [...categories.entries()]
    .map(([category, amountCents]) => ({
      category,
      amount: amountCents / 100,
      percentage: totalCents ? Number((amountCents / totalCents * 100).toFixed(1)) : 0
    }))
    .sort((left, right) => right.amount - left.amount);

  const buckets = new Map();
  daily.forEach((day) => {
    const bucketKey = period === 'week' ? getWeekStart(day.date) : day.date.slice(0, 7);
    if (!buckets.has(bucketKey)) buckets.set(bucketKey, { key: bucketKey, totalCents: 0, days: [] });
    const bucket = buckets.get(bucketKey);
    bucket.totalCents += Math.round(day.total * 100);
    bucket.days.push(day);
  });
  const bucketList = [...buckets.values()].map((bucket) => {
    const endDate = period === 'week' ? addDays(bucket.key, 6) : bucket.days[bucket.days.length - 1].date;
    return {
      from: period === 'week' ? bucket.key : bucket.days[0].date,
      to: endDate,
      label: period === 'week' ? `${formatShortDate(bucket.key)}–${formatShortDate(endDate)}` : new Intl.DateTimeFormat('en-IN', {
        timeZone: 'UTC', month: 'long', year: 'numeric'
      }).format(new Date(`${bucket.key}-01T00:00:00.000Z`)),
      total: bucket.totalCents / 100,
      days: bucket.days
    };
  });

  return {
    period,
    buckets: bucketList,
    total: totalCents / 100,
    dailyAverage: daysCount ? totalCents / 100 / daysCount : 0,
    highestDay,
    comparison: {
      previousTotal: previousTotalCents / 100,
      changePercent: previousTotalCents === 0
        ? (totalCents === 0 ? 0 : null)
        : Number(((totalCents - previousTotalCents) / previousTotalCents * 100).toFixed(1))
    },
    categoryBreakdown
  };
};

module.exports = {
  addDays,
  buildDailyInsights,
  buildInsightsSummary,
  dateKeyToUtcStart,
  getInclusiveDayCount,
  getKolkataDateKey,
  isDateKey
};