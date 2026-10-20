require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo').default || require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const { splitExpenseEntries, parseExpenseEntry, resolveSplitTags } = require('./parser');
const { calculateBalanceAudit, getId } = require('./balance');
const {
  addDays,
  buildDailyInsights,
  buildInsightsSummary,
  dateKeyToUtcStart,
  getInclusiveDayCount,
  isDateKey
} = require('./insights');

const app = express();
const PORT = process.env.PORT || 3000;
const requiredEnvironmentVariables = ['SESSION_SECRET', 'ADMIN_SECRET', 'JWT_SECRET', 'CRON_SECRET', 'TELEGRAM_WEBHOOK_SECRET'];
const missingEnvironmentVariables = requiredEnvironmentVariables.filter((name) => !process.env[name]);
if (missingEnvironmentVariables.length) {
  throw new Error(`Missing required environment variables: ${missingEnvironmentVariables.join(', ')}`);
}

const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const CRON_SECRET = process.env.CRON_SECRET;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_WEBHOOK_SECRET = process.env.TELEGRAM_WEBHOOK_SECRET;
const PUBLIC_URL = process.env.PUBLIC_URL || '';
const mongoURI = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/expense_tracker';

const getKolkataDateKey = (date = new Date()) => {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });

  const parts = formatter.formatToParts(date);
  const values = {};
  parts.forEach((part) => {
    if (part.type !== 'literal') values[part.type] = part.value;
  });
  return `${values.year}-${values.month}-${values.day}`;
};

const normalizeText = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : '');

const initializeFirebase = () => {
  if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) return;

  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    if (!admin.apps.length) {
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    }
  } catch (error) {
    console.warn('⚠️ Firebase service account not loaded:', error.message);
  }
};

initializeFirebase();

mongoose.connect(mongoURI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => console.error('❌ MongoDB Connection Error:', err));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  activeGroup: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
  joinedGroups: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Group' }],
  telegramChatId: String,
  fcmTokens: [{ type: String }],
  nickname: String,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const findUserByUsername = (username) => {
  const normalizedUsername = typeof username === 'string' ? username.trim() : '';
  if (!normalizedUsername) return null;
  const escapedUsername = normalizedUsername.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return User.findOne({ username: { $regex: `^\\s*${escapedUsername}\\s*$`, $options: 'i' } });
};

const groupSchema = new mongoose.Schema({
  name: String,
  groupCode: { type: String, required: true, unique: true },
  isRestricted: { type: Boolean, default: false },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  pendingMembers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});
const Group = mongoose.model('Group', groupSchema);

const expenseSchema = new mongoose.Schema({
  description: String,
  amount: Number,
  category: { type: String, default: 'General' },
  date: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  paidBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  groupCode: String,
  isConsumable: { type: Boolean, default: false },
  totalQuantity: { type: Number, default: 1 },
  consumedQuantity: { type: Number, default: 0 },
  splitBetween: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  source: { type: String, enum: ['app', 'telegram'], default: 'app' },
  telegramMessageId: Number,
  telegramUpdateId: Number
});
expenseSchema.index({ groupCode: 1, date: -1 });
const Expense = mongoose.model('Expense', expenseSchema);

const historySchema = new mongoose.Schema({
  groupCode: String,
  action: String,
  message: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: { type: Date, default: Date.now }
});
const History = mongoose.model('History', historySchema);

const pendingActionSchema = new mongoose.Schema({
  actionType: String,
  groupCode: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  payload: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now, expires: 600 }
});
const PendingAction = mongoose.model('PendingAction', pendingActionSchema);

const telegramUpdateIdSchema = new mongoose.Schema({
  updateId: Number,
  chatId: Number,
  messageId: Number,
  createdAt: { type: Date, default: Date.now, expires: 7 * 24 * 60 * 60 }
});
const TelegramUpdateId = mongoose.model('TelegramUpdateId', telegramUpdateIdSchema);

const telegramLinkCodeSchema = new mongoose.Schema({
  code: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now, expires: 600 }
});
const TelegramLinkCode = mongoose.model('TelegramLinkCode', telegramLinkCodeSchema);

const dailyCheckSchema = new mongoose.Schema({
  groupCode: String,
  date: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });
const DailyCheck = mongoose.model('DailyCheck', dailyCheckSchema);

const ensureGroupForUser = async (user) => {
  if (!user || !user.activeGroup) return null;
  return Group.findById(user.activeGroup);
};

const getCurrentUserFromJwt = async (authorizationHeader) => {
  if (!authorizationHeader) return null;
  const tokenValue = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.replace('Bearer ', '').trim() : authorizationHeader.trim();
  if (!tokenValue) return null;

  const payload = jwt.verify(tokenValue, JWT_SECRET);
  const user = await User.findById(payload.userId).select('-password');
  if (!user) return null;
  if (user.isBanned) {
    const err = new Error('User is banned');
    err.statusCode = 403;
    throw err;
  }
  return user;
};

const pruneInvalidFcmTokens = async (tokens = []) => {
  const uniqueTokens = [...new Set(tokens.filter(Boolean))];
  if (!uniqueTokens.length || !admin.apps.length) return uniqueTokens;

  try {
    const result = await admin.messaging().sendEachForMulticast({
      tokens: uniqueTokens,
      data: { type: 'ping' }
    });

    const validTokens = uniqueTokens.filter((_, index) => {
      const response = result.responses[index];
      if (!response || !response.error) return true;
      const invalidCodes = [
        'messaging/invalid-registration-token',
        'messaging/registration-token-not-registered'
      ];
      return !invalidCodes.includes(response.error.code);
    });

    return validTokens;
  } catch (error) {
    console.warn('FCM token validation failed:', error.message);
    return uniqueTokens;
  }
};

const sendFcmAlert = async ({ groupCode, excludeUserId, targetUserId, title, body, data = {} }) => {
  if (!admin.apps.length) return;

  const group = await Group.findOne({ groupCode }).populate('members', 'fcmTokens');
  if (!group || !group.members || !group.members.length) return;

  const memberIds = group.members
    .filter((member) => member && member._id && (
      targetUserId
        ? member._id.toString() === String(targetUserId)
        : member._id.toString() !== String(excludeUserId)
    ))
    .map((member) => member._id.toString());

  const users = await User.find({ _id: { $in: memberIds } });
  const tokens = [...new Set(users.flatMap((user) => (user.fcmTokens || []).filter(Boolean)))];

  if (!tokens.length) return;

  const validTokens = await pruneInvalidFcmTokens(tokens);
  if (!validTokens.length) return;

  try {
    await admin.messaging().sendEachForMulticast({
      tokens: validTokens,
      notification: { title, body },
      data: Object.fromEntries(Object.entries(data).map(([key, value]) => [key, String(value)]))
    });
  } catch (error) {
    console.warn('FCM send failed:', error.message);
  }
};

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: mongoURI }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 365 }
}));
app.use(passport.initialize());
app.use(passport.session());

app.use(async (req, res, next) => {
  if (req.path.startsWith('/api') && !req.user && req.headers.authorization) {
    try {
      const user = await getCurrentUserFromJwt(req.headers.authorization);
      if (!user) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      req.user = user;
      req.isAuthenticated = () => true;
      req.authMethod = 'jwt';
      return next();
    } catch (error) {
      const status = error.statusCode || 401;
      return res.status(status).json({ error: error.message || 'Invalid token' });
    }
  }
  next();
});

passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await findUserByUsername(username);
    if (!user) return done(null, false, { message: 'User not found' });
    if (user.isBanned) return done(null, false, { message: 'You are BANNED.' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return done(null, false, { message: 'Incorrect password' });
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (e) {
    done(e);
  }
});

const ensureAuth = async (req, res, next) => {
  if (req.user && !req.user.isBanned) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ error: 'Not Authorized' });
};

const ensureAdmin = async (req, res, next) => {
  if (req.user && req.user.isAdmin) return next();
  if (req.isAuthenticated && req.isAuthenticated() && req.user && req.user.isAdmin) return next();
  return res.status(403).json({ error: 'Admins Only' });
};

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/api/user', async (req, res) => {
  if (!req.user) return res.status(401).json({ user: null });
  if (req.user.isBanned) return res.status(403).json({ error: 'User is banned' });
  const group = await ensureGroupForUser(req.user);
  return res.json({ user: { ...req.user.toObject(), groupCode: group ? group.groupCode : null } });
});

app.post('/auth/login', passport.authenticate('local'), async (req, res) => {
  if (!req.user.activeGroup && req.user.joinedGroups && req.user.joinedGroups.length > 0) {
    req.user.activeGroup = req.user.joinedGroups[0];
    await req.user.save();
  } else if (!req.user.activeGroup) {
    const group = await Group.findOne({ members: req.user._id });
    if (group) {
      req.user.joinedGroups = [group._id];
      req.user.activeGroup = group._id;
      await req.user.save();
    }
  }
  res.json({ success: true, user: req.user });
});

app.post('/api/mobile/login', async (req, res) => {
  const { username, password } = req.body || {};
  try {
    const user = await findUserByUsername(username);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (user.isBanned) return res.status(403).json({ error: 'User is banned' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Incorrect password' });

    const token = jwt.sign({ userId: user._id.toString(), username: user.username }, JWT_SECRET, { expiresIn: '365d' });
    res.json({
      token,
      user: {
        _id: user._id,
        username: user.username,
        isAdmin: user.isAdmin,
        isBanned: user.isBanned,
        activeGroup: user.activeGroup,
        joinedGroups: user.joinedGroups,
        nickname: user.nickname,
        telegramChatId: user.telegramChatId
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message || 'Login failed' });
  }
});

app.post('/api/mobile/register-group', async (req, res) => {
  const { username, password, groupCode, adminSecret } = req.body || {};
  if (!username || !password || !groupCode) return res.status(400).json({ error: 'Username, password, and group code are required' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    if (await User.findOne({ username })) return res.status(409).json({ error: 'Username taken' });
    if (await Group.findOne({ groupCode })) return res.status(409).json({ error: 'Group code already exists' });

    const user = new User({
      username: String(username).trim(),
      password: await bcrypt.hash(password, 10),
      isAdmin: adminSecret === ADMIN_SECRET
    });
    const group = new Group({
      name: `${String(groupCode).trim()}'s House`,
      groupCode: String(groupCode).trim(),
      members: [user._id]
    });
    await group.save();
    user.joinedGroups = [group._id];
    user.activeGroup = group._id;
    await user.save();

    const token = jwt.sign({ userId: user._id.toString(), username: user.username }, JWT_SECRET, { expiresIn: '365d' });
    return res.status(201).json({
      token,
      user: {
        _id: user._id,
        username: user.username,
        isAdmin: user.isAdmin,
        isBanned: false,
        activeGroup: user.activeGroup,
        joinedGroups: user.joinedGroups,
        nickname: user.nickname,
        telegramChatId: user.telegramChatId
      }
    });
  } catch (error) {
    return res.status(500).json({ error: error.message || 'Group registration failed' });
  }
});

app.post('/api/mobile/join-group', async (req, res) => {
  const { username, password, groupCode } = req.body || {};
  if (!username || !password || !groupCode) return res.status(400).json({ error: 'Username, password, and group code are required' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    if (await User.findOne({ username })) return res.status(409).json({ error: 'Username taken' });
    const group = await Group.findOne({ groupCode: String(groupCode).trim() });
    if (!group) return res.status(404).json({ error: 'Group not found' });

    const user = new User({
      username: String(username).trim(),
      password: await bcrypt.hash(password, 10),
      isAdmin: false
    });
    if (group.isRestricted) {
      group.pendingMembers.push(user._id);
      await group.save();
      await user.save();
    } else {
      group.members.push(user._id);
      user.joinedGroups = [group._id];
      user.activeGroup = group._id;
      await group.save();
      await user.save();
    }
    const token = jwt.sign({ userId: user._id.toString(), username: user.username }, JWT_SECRET, { expiresIn: '365d' });
    return res.status(201).json({
      token,
      pendingApproval: group.isRestricted,
      message: group.isRestricted ? 'Request sent. Wait for admin approval.' : `Joined ${group.name}.`,
      user: {
        _id: user._id,
        username: user.username,
        isAdmin: false,
        isBanned: false,
        activeGroup: user.activeGroup,
        joinedGroups: user.joinedGroups,
        nickname: user.nickname,
        telegramChatId: user.telegramChatId
      }
    });
  } catch (error) {
    return res.status(500).json({ error: error.message || 'Could not join group' });
  }
});

app.post('/auth/logout', (req, res) => req.logout(() => res.json({ success: true })));

app.post('/auth/register-group', async (req, res) => {
  const { username, password, groupCode, adminSecret } = req.body;
  try {
    if (!username || !password || !groupCode) return res.status(400).json({ error: 'Missing fields' });
    if (await User.findOne({ username })) return res.status(400).json({ error: 'Username taken' });
    if (await Group.findOne({ groupCode })) return res.status(400).json({ error: 'Group exists' });

    const isAdmin = adminSecret === ADMIN_SECRET;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, isAdmin });

    const newGroup = new Group({ name: `${groupCode}'s House`, groupCode, members: [newUser._id] });
    await newGroup.save();

    newUser.joinedGroups = [newGroup._id];
    newUser.activeGroup = newGroup._id;
    await newUser.save();

    req.login(newUser, (err) => res.json({ success: true, user: newUser }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/auth/join-group', async (req, res) => {
  const { username, password, groupCode } = req.body;
  try {
    if (await User.findOne({ username })) return res.status(400).json({ error: 'Username taken' });
    const group = await Group.findOne({ groupCode });
    if (!group) return res.status(404).json({ error: 'Group not found' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, isAdmin: false });

    if (group.isRestricted) {
      group.pendingMembers.push(newUser._id);
      await newUser.save();
      await group.save();
      return res.json({ success: true, msg: 'Request Sent. Wait for Admin Approval.' });
    }

    group.members.push(newUser._id);
    await group.save();
    newUser.joinedGroups = [group._id];
    newUser.activeGroup = group._id;
    await newUser.save();
    req.login(newUser, (err) => res.json({ success: true, user: newUser }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/user/join-existing', ensureAuth, async (req, res) => {
  const { groupCode } = req.body;
  try {
    const group = await Group.findOne({ groupCode });
    if (!group) return res.status(404).json({ error: 'Group not found' });

    if (req.user.joinedGroups.includes(group._id)) {
      return res.status(400).json({ error: 'You are already in this group!' });
    }

    if (group.isRestricted) {
      if (!group.pendingMembers.includes(req.user._id)) {
        group.pendingMembers.push(req.user._id);
        await group.save();
      }
      return res.json({ success: true, msg: 'Request Sent to Admin.' });
    }

    group.members.push(req.user._id);
    await group.save();

    req.user.joinedGroups.push(group._id);
    req.user.activeGroup = group._id;
    await req.user.save();

    res.json({ success: true, msg: `Joined ${group.name}!` });
  } catch (e) {
    res.status(500).json({ error: 'Join failed' });
  }
});

app.post('/api/user/switch-group', ensureAuth, async (req, res) => {
  const { groupId } = req.body;
  const group = await Group.findById(groupId);
  if (!group || !group.members.includes(req.user._id)) {
    return res.status(403).json({ error: 'You are not in this group' });
  }
  req.user.activeGroup = groupId;
  await req.user.save();
  res.json({ success: true, groupName: group.name });
});

app.get('/api/user/groups', ensureAuth, async (req, res) => {
  await req.user.populate('joinedGroups', 'name groupCode');
  res.json({ groups: req.user.joinedGroups, activeGroupId: req.user.activeGroup });
});

app.post('/api/user/nickname', ensureAuth, async (req, res) => {
  const nickname = typeof req.body.nickname === 'string' ? req.body.nickname.trim() : '';
  if (!nickname) return res.status(400).json({ error: 'Nickname is required' });
  if (/^(me|all)$/i.test(nickname)) {
    return res.status(400).json({ error: 'Nickname cannot be “me” or “all”' });
  }
  if (nickname.length > 32) return res.status(400).json({ error: 'Nickname must be 32 characters or fewer' });

  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.status(404).json({ error: 'Active group not found' });
  const otherMembers = group.members.filter((id) => String(id) !== String(req.user._id));
  const existing = await User.findOne({
    _id: { $in: otherMembers },
    nickname: { $regex: `^${nickname.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' }
  });
  if (existing) return res.status(409).json({ error: 'That nickname is already used in this group' });

  req.user.nickname = nickname;
  await req.user.save();
  return res.json({ success: true, nickname: req.user.nickname });
});

app.get('/api/expenses', ensureAuth, async (req, res) => {
  if (!req.user.activeGroup) return res.json([]);

  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.json([]);

  const expenses = await Expense.find({ groupCode: group.groupCode })
    .populate('paidBy', 'username')
    .sort({ date: -1 });
  res.json(expenses);
});

app.post('/api/expenses', ensureAuth, async (req, res) => {
  if (!req.user.activeGroup) return res.status(400).json({ error: 'No Active Group' });

  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  if (req.body.isEdit) {
    const oldExpense = await Expense.findById(req.body.expenseId);
    if (!oldExpense) return res.status(404).json({ error: 'Expense not found' });
    if (oldExpense.groupCode !== group.groupCode) {
      return res.status(403).json({ error: 'This expense does not belong to your active group' });
    }

    const newData = req.body.newData || {};
    const description = typeof newData.description === 'string' ? newData.description.trim() : '';
    const amount = Number(newData.amount);
    const splitBetween = Array.isArray(newData.splitBetween) ? [...new Set(newData.splitBetween.map(String))] : [];
    const groupMemberIds = new Set(group.members.map(String));
    if (!description || !Number.isFinite(amount) || amount <= 0 || splitBetween.length === 0) {
      return res.status(400).json({ error: 'Description, positive amount, and non-empty split are required' });
    }
    if (splitBetween.some((id) => !groupMemberIds.has(id))) {
      return res.status(400).json({ error: 'Split members must belong to the active group' });
    }
    const updated = await Expense.findByIdAndUpdate(req.body.expenseId, {
      $set: {
        description,
        amount,
        category: typeof newData.category === 'string' && newData.category.trim() ? newData.category.trim() : 'General',
        splitBetween,
        date: newData.date ? new Date(newData.date) : oldExpense.date
      }
    }, { new: true, runValidators: true });
    await History.create({
      groupCode: group.groupCode,
      action: 'EDIT',
      message: `edited "${oldExpense.description}" (₹${oldExpense.amount} → ₹${updated.amount})`,
      user: req.user._id
    });
    await sendFcmAlert({
      groupCode: group.groupCode,
      excludeUserId: req.user._id,
      title: 'Expense update',
      body: `${req.user.username} edited ${updated.description} ₹${updated.amount}`
    });
    return res.json({ success: true, msg: 'Updated', expense: updated });
  }

  const description = typeof req.body.description === 'string' ? req.body.description.trim() : '';
  const amount = Number(req.body.amount);
  const splitInput = Array.isArray(req.body.splitBetween) ? req.body.splitBetween : [];
  const splitBetween = [...new Set(
    (splitInput.length > 0 ? splitInput : group.members).map((member) => String(member))
  )];
  const validDate = req.body.date ? new Date(req.body.date) : new Date();

  if (!description || !Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Description and a positive amount are required' });
  }
  if (Number.isNaN(validDate.getTime())) {
    return res.status(400).json({ error: 'A valid expense date is required' });
  }
  if (splitBetween.length === 0) {
    return res.status(400).json({ error: 'Choose at least one group member to split with' });
  }
  const groupMemberIds = new Set(group.members.map((member) => String(member)));
  if (splitBetween.some((memberId) => !groupMemberIds.has(memberId))) {
    return res.status(400).json({ error: 'Split members must belong to the active group' });
  }

  const newExpense = new Expense({
    description,
    amount,
    category: typeof req.body.category === 'string' && req.body.category.trim()
      ? req.body.category.trim()
      : 'General',
    source: 'app',
    date: validDate,
    createdAt: new Date(),
    paidBy: req.user._id,
    groupCode: group.groupCode,
    splitBetween
  });
  await newExpense.save();

  await History.create({
    groupCode: group.groupCode,
    action: 'ADD',
    message: `added "${newExpense.description}" (₹${newExpense.amount})`,
    user: req.user._id
  });

  await newExpense.populate('paidBy', 'username nickname');
  res.json(newExpense);
  setImmediate(() => {
    sendFcmAlert({
      groupCode: group.groupCode,
      excludeUserId: req.user._id,
      title: 'Expense update',
      body: `${req.user.username} added ${newExpense.description} ₹${newExpense.amount}`
    }).catch((error) => console.warn('Expense push failed:', error.message));
  });
});

app.post('/api/expenses/delete', ensureAuth, async (req, res) => {
  const { expenseId } = req.body;
  const expense = await Expense.findById(expenseId);
  if (!expense) return res.status(404).json({ error: 'Not found' });

  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (expense.groupCode !== group.groupCode) {
    return res.status(403).json({ error: 'This expense does not belong to your active group' });
  }

  await Expense.findByIdAndDelete(expenseId);

  await History.create({
    groupCode: group.groupCode,
    action: 'DELETE',
    message: `deleted "${expense.description}" (₹${expense.amount})`,
    user: req.user._id
  });

  await sendFcmAlert({
    groupCode: group.groupCode,
    excludeUserId: req.user._id,
    title: 'Expense update',
    body: `${req.user.username} deleted ${expense.description} ₹${expense.amount}`
  });

  return res.json({ success: true, msg: 'Deleted' });
});

app.get('/api/group/history', ensureAuth, async (req, res) => {
  if (!req.user.activeGroup) return res.json([]);
  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.json([]);

  const logs = await History.find({ groupCode: group.groupCode }).populate('user', 'username').sort({ date: -1 }).limit(50);
  res.json(logs);
});

app.post('/api/expenses/consume', ensureAuth, async (req, res) => {
  const { expenseId } = req.body;
  const expense = await Expense.findById(expenseId);
  if (!expense) return res.status(404).json({ error: 'Expense not found' });

  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (expense.groupCode !== group.groupCode) {
    return res.status(403).json({ error: 'This expense does not belong to your active group' });
  }

  if (expense.consumedQuantity < expense.totalQuantity) {
    expense.consumedQuantity += 1;
    await expense.save();
  }
  res.json({ success: true, expense });
});

const getGroupBalanceAudit = async (group) => {
  const expenses = await Expense.find({ groupCode: group.groupCode })
    .select('_id amount paidBy splitBetween')
    .lean();
  const participantIds = new Set((group.members || []).map(getId).filter(Boolean));
  expenses.forEach((expense) => {
    if (expense.paidBy) participantIds.add(getId(expense.paidBy));
    (expense.splitBetween || []).forEach((id) => participantIds.add(getId(id)));
  });
  const users = await User.find({ _id: { $in: [...participantIds] } })
    .select('_id username nickname')
    .lean();
  const membersById = new Map(users.map((user) => [String(user._id), user]));
  (group.members || []).forEach((member) => {
    const id = getId(member);
    if (id && !membersById.has(id)) membersById.set(id, typeof member === 'object' ? member : { _id: id });
  });
  const groupMembers = [...participantIds].map((id) => membersById.get(id) || { _id: id, username: 'Unknown' });
  return calculateBalanceAudit({ expenses, groupMembers });
};

const getUserBalanceAudit = async (user) => {
  if (!user.activeGroup) return null;
  const group = await Group.findById(user.activeGroup).select('groupCode members').lean();
  if (!group) return null;
  return getGroupBalanceAudit(group);
};

app.get('/api/reports/debts', ensureAuth, async (req, res) => {
  const audit = await getUserBalanceAudit(req.user);
  return res.json(audit ? audit.settlements : []);
});

app.get('/api/reports/audit', ensureAuth, async (req, res) => {
  const audit = await getUserBalanceAudit(req.user);
  if (!audit) {
    return res.json({ members: [], settlements: [], sumOfNets: 0 });
  }
  return res.json(audit);
});

app.get('/api/reports/my-balance', ensureAuth, async (req, res) => {
  const audit = await getUserBalanceAudit(req.user);
  const userId = String(req.user._id);
  const balance = audit ? audit.members.find((member) => member.id === userId)?.net || 0 : 0;
  return res.json({ balance });
});

const parseInsightsRange = (from, to) => {
  if (!isDateKey(from) || !isDateKey(to) || from > to) return null;
  const dayCount = getInclusiveDayCount(from, to);
  if (dayCount > 400) return null;
  return {
    from,
    to,
    start: dateKeyToUtcStart(from),
    end: dateKeyToUtcStart(addDays(to, 1)),
    dayCount
  };
};

const loadInsightExpenses = (groupCode, from, to) => {
  const start = dateKeyToUtcStart(from);
  const end = dateKeyToUtcStart(addDays(to, 1));
  return Expense.find({
    groupCode,
    $or: [
      { date: { $gte: start, $lt: end } },
      { date: null, createdAt: { $gte: start, $lt: end } }
    ]
  })
    .select('_id description amount category date createdAt paidBy splitBetween')
    .populate('paidBy', 'username nickname')
    .lean();
};

app.get('/api/insights/daily', ensureAuth, async (req, res) => {
  const range = parseInsightsRange(req.query.from, req.query.to);
  if (!range) return res.status(400).json({ error: 'Valid from/to dates are required (maximum 400 days)' });
  if (!req.user.activeGroup) return res.status(400).json({ error: 'No active group' });

  const group = await Group.findById(req.user.activeGroup).populate('members', 'username nickname').lean();
  if (!group) return res.status(404).json({ error: 'Active group not found' });
  const expenses = await loadInsightExpenses(group.groupCode, range.from, range.to);
  const mode = req.query.view === 'paid' ? 'paid' : 'share';
  return res.json(buildDailyInsights({
    expenses,
    groupMembers: group.members || [],
    userId: String(req.user._id),
    from: range.from,
    to: range.to,
    mode
  }));
});

app.get('/api/insights/summary', ensureAuth, async (req, res) => {
  const period = req.query.period;
  if (period !== 'week' && period !== 'month') {
    return res.status(400).json({ error: 'period must be week or month' });
  }
  const range = parseInsightsRange(req.query.from, req.query.to);
  if (!range) return res.status(400).json({ error: 'Valid from/to dates are required (maximum 400 days)' });
  if (!req.user.activeGroup) return res.status(400).json({ error: 'No active group' });

  const group = await Group.findById(req.user.activeGroup).populate('members', 'username nickname').lean();
  if (!group) return res.status(404).json({ error: 'Active group not found' });
  const previousFrom = addDays(range.from, -range.dayCount);
  const previousTo = addDays(range.from, -1);
  const expenses = await loadInsightExpenses(group.groupCode, previousFrom, range.to);
  const mode = req.query.view === 'paid' ? 'paid' : 'share';
  const allDays = buildDailyInsights({
    expenses,
    groupMembers: group.members || [],
    userId: String(req.user._id),
    from: previousFrom,
    to: range.to,
    mode
  });
  const daily = allDays.filter((day) => day.date >= range.from);
  const previousDaily = allDays.filter((day) => day.date <= previousTo);
  return res.json(buildInsightsSummary({ daily, previousDaily, period }));
});

app.get('/api/group/members', ensureAuth, async (req, res) => {
  if (!req.user.activeGroup) return res.json([]);
  const group = await Group.findById(req.user.activeGroup).populate('members', 'username nickname isAdmin isBanned');
  res.json(group ? group.members : []);
});

app.get('/api/admin/pending', ensureAdmin, async (req, res) => {
  if (!req.user.activeGroup) return res.json({ pending: [], isRestricted: false });
  const group = await Group.findById(req.user.activeGroup).populate('pendingMembers', 'username');
  res.json({ pending: group ? group.pendingMembers : [], isRestricted: group ? group.isRestricted : false });
});

app.post('/api/admin/toggle-lock', ensureAdmin, async (req, res) => {
  if (!req.user.activeGroup) return res.status(400).json({ error: 'No Active Group' });
  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  group.isRestricted = !group.isRestricted;
  await group.save();
  res.json({ success: true, isRestricted: group.isRestricted });
});

app.post('/api/admin/approve', ensureAdmin, async (req, res) => {
  if (!req.user.activeGroup) return res.status(400).json({ error: 'No Active Group' });
  const { userId, approve } = req.body;
  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  group.pendingMembers = group.pendingMembers.filter((id) => id.toString() !== userId);
  if (approve) {
    group.members.push(userId);
    await User.findByIdAndUpdate(userId, { $push: { joinedGroups: group._id }, activeGroup: group._id });
  } else {
    await User.findByIdAndDelete(userId);
  }
  await group.save();
  res.json({ success: true });
});

app.post('/api/admin/ban-user', ensureAdmin, async (req, res) => {
  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (String(req.body.userId) === String(req.user._id) || !group.members.some((id) => String(id) === String(req.body.userId))) {
    return res.status(400).json({ error: 'Choose another member of this group' });
  }
  await User.findByIdAndUpdate(req.body.userId, { isBanned: true });
  res.json({ success: true });
});

app.post('/api/admin/reset-password', ensureAdmin, async (req, res) => {
  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (!group.members.some((id) => String(id) === String(req.body.userId))) {
    return res.status(400).json({ error: 'Choose a member of this group' });
  }
  if (typeof req.body.newPassword !== 'string' || req.body.newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  const hashed = await bcrypt.hash(req.body.newPassword, 10);
  await User.findByIdAndUpdate(req.body.userId, { password: hashed });
  res.json({ success: true });
});

app.post('/api/mobile/register-fcm', ensureAuth, async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Firebase token required' });

  const user = await User.findById(req.user._id);
  const tokens = Array.isArray(user.fcmTokens) ? user.fcmTokens : [];
  const uniqueTokens = [...new Set([...(tokens || []), token].filter(Boolean))];
  user.fcmTokens = uniqueTokens;
  await user.save();

  if (admin.apps.length) {
    try {
      const current = await pruneInvalidFcmTokens(uniqueTokens);
      user.fcmTokens = current;
      await user.save();
    } catch (error) {
      console.warn('FCM registration cleanup failed:', error.message);
    }
  }

  res.json({ success: true, tokenCount: user.fcmTokens.length });
});

app.post('/api/mobile/nothing-today', ensureAuth, async (req, res) => {
  if (!req.user.activeGroup) return res.status(400).json({ error: 'No Active Group' });

  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  const today = getKolkataDateKey(new Date());
  await DailyCheck.findOneAndUpdate(
    { groupCode: group.groupCode, date: today, userId: req.user._id },
    { $set: { groupCode: group.groupCode, date: today, userId: req.user._id } },
    { upsert: true, new: true }
  );

  res.json({ success: true, marked: true });
});

app.get('/api/expenses/catchup', ensureAuth, async (req, res) => {
  if (!req.user.activeGroup) return res.json([]);

  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.json([]);

  const days = [];
  for (let i = 6; i >= 0; i -= 1) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateKey = getKolkataDateKey(d);
    const from = new Date(`${dateKey}T00:00:00+05:30`);
    const to = new Date(`${dateKey}T23:59:59.999+05:30`);
    const count = await Expense.countDocuments({ groupCode: group.groupCode, date: { $gte: from, $lt: to } });
    const nothingMarked = await DailyCheck.exists({ groupCode: group.groupCode, date: dateKey, userId: req.user._id });
    days.push({ date: dateKey, count, nothingToday: !!nothingMarked });
  }

  res.json(days);
});

app.get('/api/expenses/suggestions', ensureAuth, async (req, res) => {
  if (!req.user.activeGroup) return res.json([]);
  const group = await Group.findById(req.user.activeGroup);
  if (!group) return res.json([]);

  const expenses = await Expense.find({ groupCode: group.groupCode, paidBy: req.user._id }).sort({ date: -1 });
  const buckets = new Map();
  expenses.forEach((exp) => {
    const key = normalizeText(exp.description);
    if (!key) return;
    if (!buckets.has(key)) {
      buckets.set(key, { description: exp.description.trim(), amount: exp.amount, count: 0 });
    }
    buckets.get(key).count += 1;
    buckets.get(key).amount = exp.amount;
  });

  const suggestions = [...buckets.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, 12)
    .map(({ description, amount }) => ({ description, amount }));

  res.json(suggestions);
});

app.get('/api/cron/reminders', async (req, res) => {
  if (req.query.key !== CRON_SECRET) {
    return res.status(403).json({ error: 'Invalid key' });
  }

  setImmediate(async () => {
    try {
      const groups = await Group.find({});
      const todayKey = getKolkataDateKey(new Date());

      for (const group of groups) {
        const from = new Date(`${todayKey}T00:00:00+05:30`);
        const to = new Date(`${todayKey}T23:59:59.999+05:30`);
        const anyExpenseToday = await Expense.exists({
          groupCode: group.groupCode,
          date: { $gte: from, $lt: to }
        });

        if (anyExpenseToday) continue;

        const members = await User.find({ _id: { $in: group.members } });
        for (const member of members) {
          const alreadyChecked = await DailyCheck.exists({ groupCode: group.groupCode, date: todayKey, userId: member._id });
          if (alreadyChecked) continue;

          await sendFcmAlert({
            groupCode: group.groupCode,
            targetUserId: member._id,
            title: 'Daily reminder',
            body: "You haven't added any expenses today.",
            data: { type: 'daily' }
          });

          if (member.telegramChatId) {
            await sendTelegramMessage(
              member.telegramChatId,
              "You haven't added any expenses today.",
              {
                inline_keyboard: [[
                  { text: 'Nothing today', callback_data: `nothing:${group._id}` }
                ]]
              }
            );
          }
        }
      }
    } catch (error) {
      console.warn('Reminder job failed:', error.message);
    }
  });

  return res.status(200).json({ ok: true });
});

const telegramApi = async (method, payload = {}, isJson = true) => {
  if (!TELEGRAM_BOT_TOKEN) return null;

  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`;
  const options = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  };

  if (!isJson) {
    delete options.headers;
    delete options.body;
    options.body = payload;
  }

  const response = await fetch(url, options);
  const data = await response.json();
  return data;
};

const setTelegramWebhook = async () => {
  if (!TELEGRAM_BOT_TOKEN || !PUBLIC_URL) return;

  const endpoint = `${PUBLIC_URL.replace(/\/$/, '')}/telegram/webhook/${TELEGRAM_WEBHOOK_SECRET}`;
  return telegramApi('setWebhook', { url: endpoint });
};

const sendTelegramMessage = async (chatId, text, replyMarkup = null) => {
  if (!chatId || !TELEGRAM_BOT_TOKEN) return null;

  const payload = { chat_id: chatId, text, parse_mode: 'HTML' };
  if (replyMarkup) payload.reply_markup = replyMarkup;
  return telegramApi('sendMessage', payload);
};

const isTelegramUpdateSeen = async (updateId, chatId, messageId) => {
  const existing = await TelegramUpdateId.findOne({ updateId, chatId, messageId });
  if (existing) return true;

  await TelegramUpdateId.create({ updateId, chatId, messageId });
  return false;
};

app.post('/api/telegram/link-code', ensureAuth, async (req, res) => {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  await TelegramLinkCode.deleteMany({ userId: req.user._id });
  await TelegramLinkCode.create({ code, userId: req.user._id });
  res.json({ success: true, code, expiresIn: 600 });
});

app.post('/telegram/webhook/:secret', async (req, res) => {
  if (req.params.secret !== TELEGRAM_WEBHOOK_SECRET) {
    return res.status(403).json({ ok: false });
  }

  const update = req.body || {};
  const callbackQuery = update.callback_query;
  const message = update.message || update.edited_message;

  if (callbackQuery) {
    const updateId = Number(update.update_id || 0);
    const chatId = Number(callbackQuery.from && callbackQuery.from.id);
    const messageId = Number(callbackQuery.message && callbackQuery.message.message_id);
    const seen = await isTelegramUpdateSeen(updateId, chatId, messageId);
    if (seen) return res.status(200).send('OK');

    const [type, payload] = (callbackQuery.data || '').split(':');
    const user = await User.findOne({ telegramChatId: String(callbackQuery.from.id) });
    if (type === 'undo') {
      const expense = await Expense.findById(payload);
      const group = user && expense
        ? await Group.findOne({ groupCode: expense.groupCode, members: user._id })
        : null;
      const isWithinUndoWindow = expense && expense.createdAt
        && Date.now() - expense.createdAt.getTime() <= 5 * 60 * 1000;
      if (expense && user && group && isWithinUndoWindow && String(expense.paidBy) === String(user._id)) {
          await Expense.findByIdAndDelete(expense._id);
          await History.create({
            groupCode: expense.groupCode,
            action: 'DELETE',
            message: `deleted "${expense.description}" (₹${expense.amount}) via Telegram`,
            user: user._id
          });
          await sendFcmAlert({
            groupCode: group.groupCode,
            excludeUserId: user._id,
            title: 'Expense removed',
            body: `${user.nickname || user.username} removed ${expense.description} ₹${expense.amount}`
          });
      }
      await telegramApi('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: expense && user && group && isWithinUndoWindow ? 'Expense removed.' : 'This undo action has expired or is unavailable.'
      });
    } else if (type === 'nothing') {
      const group = user ? await Group.findOne({ _id: payload, members: user._id }) : null;
      if (group) {
        await DailyCheck.findOneAndUpdate(
          { groupCode: group.groupCode, date: getKolkataDateKey(new Date()), userId: user._id },
          { $setOnInsert: { groupCode: group.groupCode, date: getKolkataDateKey(new Date()), userId: user._id } },
          { upsert: true, new: true }
        );
      }
      await telegramApi('answerCallbackQuery', {
        callback_query_id: callbackQuery.id,
        text: group ? 'Marked as nothing today.' : 'This action is unavailable for your account.'
      });
    } else {
      await telegramApi('answerCallbackQuery', { callback_query_id: callbackQuery.id });
    }

    return res.status(200).send('OK');
  }

  if (!message || !message.text) return res.status(200).send('OK');

  const updateId = Number(update.update_id || 0);
  const chatId = Number(message.chat && message.chat.id);
  const messageId = Number(message.message_id || 0);
  const seen = await isTelegramUpdateSeen(updateId, chatId, messageId);
  if (seen) return res.status(200).send('OK');

  const text = message.text.trim();
  const lower = text.toLowerCase();
  if (lower.startsWith('/start')) {
    const startMatch = text.match(/^\/start(?:@\w+)?(?:\s+(\d{6}))?$/i);
    const code = startMatch && startMatch[1];
    if (!code) {
      await sendTelegramMessage(chatId, 'Open Settings → Connect Telegram in the app and send the generated code with /start.');
      return res.status(200).send('OK');
    }

    const linkRecord = await TelegramLinkCode.findOne({ code });
    if (linkRecord) {
      await User.findByIdAndUpdate(linkRecord.userId, { telegramChatId: String(chatId) });
      await TelegramLinkCode.deleteOne({ _id: linkRecord._id });
      await sendTelegramMessage(chatId, '✅ Telegram linked successfully.');
    } else {
      await sendTelegramMessage(chatId, 'This link code is invalid or expired.');
    }
    return res.status(200).send('OK');
  }

  const senderUser = await User.findOne({ telegramChatId: String(chatId) });
  if (!senderUser) {
    await sendTelegramMessage(chatId, 'Please connect this chat in the app first via Settings → Connect Telegram.');
    return res.status(200).send('OK');
  }

  if (!senderUser.activeGroup) {
    await sendTelegramMessage(chatId, 'You do not have an active group yet.');
    return res.status(200).send('OK');
  }

  const group = await Group.findById(senderUser.activeGroup).populate('members', 'username nickname _id');
  if (!group) {
    await sendTelegramMessage(chatId, 'Your active group is missing.');
    return res.status(200).send('OK');
  }

  const commandMatch = text.match(/^\/(\w+)(?:\s+(.*))?$/);
  if (commandMatch) {
    const [, cmd, argumentText] = commandMatch;

    if (cmd === 'today') {
      const todayKey = getKolkataDateKey(new Date());
      const start = new Date(`${todayKey}T00:00:00+05:30`);
      const end = new Date(`${todayKey}T23:59:59.999+05:30`);
      const expenses = await Expense.find({ groupCode: group.groupCode, date: { $gte: start, $lt: end } }).populate('paidBy', 'username nickname');
      if (!expenses.length) {
        await sendTelegramMessage(chatId, 'No expenses added today.');
      } else {
        const lines = expenses.map((expense) => `${expense.description} ₹${expense.amount} • ${expense.paidBy && (expense.paidBy.nickname || expense.paidBy.username)}`);
        await sendTelegramMessage(chatId, `Today:\n${lines.join('\n')}`);
      }
      return res.status(200).send('OK');
    }

    if (cmd === 'members') {
      const names = group.members.map((member) => `${member.username || member.nickname || 'Member'}`).join(', ');
      await sendTelegramMessage(chatId, `Members: ${names}`);
      return res.status(200).send('OK');
    }

    if (cmd === 'balance') {
      const audit = await getGroupBalanceAudit(group);
      const rows = audit.settlements.map(({ from, to, amount }) => `${from} owes ${to} ₹${amount.toFixed(2)}`);
      await sendTelegramMessage(chatId, rows.join('\n') || 'Everyone is settled up.');
      return res.status(200).send('OK');
    }

    if (cmd === 'undo') {
      const expense = await Expense.findOne({ groupCode: group.groupCode, paidBy: senderUser._id }).sort({ date: -1 });
      if (!expense) {
        await sendTelegramMessage(chatId, 'No recent expense found to undo.');
      } else {
        await Expense.findByIdAndDelete(expense._id);
        await History.create({
          groupCode: group.groupCode,
          action: 'DELETE',
          message: `deleted "${expense.description}" via Telegram`,
          user: senderUser._id
        });
        await sendTelegramMessage(chatId, '✅ Last expense removed.');
      }
      return res.status(200).send('OK');
    }

    if (cmd === 'nick') {
      const nickname = (argumentText || '').trim();
      if (!nickname || nickname.toLowerCase() === 'me' || nickname.toLowerCase() === 'all') {
        await sendTelegramMessage(chatId, 'Nickname must not be “me” or “all”.');
        return res.status(200).send('OK');
      }

      const existing = await User.findOne({
        activeGroup: senderUser.activeGroup,
        nickname: { $regex: new RegExp(`^${nickname}$`, 'i') },
        _id: { $ne: senderUser._id }
      });
      if (existing) {
        await sendTelegramMessage(chatId, 'That nickname is already taken in this group.');
        return res.status(200).send('OK');
      }
      senderUser.nickname = nickname;
      await senderUser.save();
      await sendTelegramMessage(chatId, `✅ Nickname updated to ${nickname}.`);
      return res.status(200).send('OK');
    }

    if (cmd === 'help') {
      const helpText = [
        '/today — today\'s entries',
        '/balance — who owes whom',
        '/undo — delete your last expense',
        '/members — list members',
        '/nick <name> — set nickname',
        '/help — show help',
        'Expense format examples: @all milk 20, @rahul dal 40, @me coffee 50'
      ].join('\n');
      await sendTelegramMessage(chatId, helpText);
      return res.status(200).send('OK');
    }
  }

  const entries = splitExpenseEntries(text);
  const validEntries = [];
  const failedEntries = [];

  for (const entry of entries) {
    const parsed = parseExpenseEntry(entry);
    if (!parsed) {
      failedEntries.push(`${entry} (invalid entry)`);
      continue;
    }

    const resolution = resolveSplitTags({
      tags: parsed.tags,
      sender: {
        _id: senderUser._id,
        username: senderUser.username,
        nickname: senderUser.nickname || senderUser.username
      },
      groupMembers: group.members.map((member) => ({
        _id: member._id,
        username: member.username,
        nickname: member.nickname || member.username
      }))
    });

    if (!resolution.ok) {
      failedEntries.push(`${parsed.description} ${parsed.amount} (${resolution.error && resolution.error.type === 'ambiguous' ? 'ambiguous name' : 'unknown name'})`);
      continue;
    }

    const newExpense = new Expense({
      description: parsed.description,
      amount: parsed.amount,
      category: 'General',
      paidBy: senderUser._id,
      groupCode: group.groupCode,
      date: new Date(message.date * 1000),
      createdAt: new Date(message.date * 1000),
      splitBetween: resolution.splitBetween,
      source: 'telegram',
      telegramMessageId: message.message_id,
      telegramUpdateId: update.update_id
    });

    await newExpense.save();
    validEntries.push(newExpense);
  }

  if (validEntries.length) {
    const savedLines = validEntries.map((expense) => {
      const parts = expense.splitBetween && expense.splitBetween.length > 0 ? expense.splitBetween.length > 1 ? `${expense.splitBetween.length} people` : 'personal' : 'all';
      const stamp = new Date(expense.date).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour: 'numeric', minute: '2-digit', day: 'numeric', month: 'short' });
      return `✅ ${expense.description} ₹${expense.amount} • ${parts} • ${stamp}`;
    });

    await sendTelegramMessage(chatId, savedLines.join('\n'));
  }

  if (failedEntries.length) {
    const failText = failedEntries.length ? `Could not save:\n${failedEntries.join('\n')}` : '';
    await sendTelegramMessage(chatId, failText);
  }

  return res.status(200).send('OK');
});

app.use((error, req, res, next) => {
  if (!req.path.startsWith('/api/')) return next(error);
  if (res.headersSent) return next(error);

  const candidateStatus = error.statusCode || error.status;
  const status = Number.isInteger(candidateStatus) && candidateStatus >= 400 && candidateStatus <= 599
    ? candidateStatus
    : 500;

  if (status >= 500) {
    console.error(`Unhandled API error for ${req.method} ${req.path}:`, error.stack || error.message);
  }

  return res.status(status).json({
    error: status >= 500 ? 'Internal server error' : error.message
  });
});

const initializeTelegram = async () => {
  if (!TELEGRAM_BOT_TOKEN || !PUBLIC_URL) return;
  try {
    const result = await setTelegramWebhook();
    if (!result || !result.ok) {
      throw new Error(result && result.description ? result.description : 'Telegram did not confirm webhook setup.');
    }
    console.log('✅ Telegram webhook configured');
  } catch (error) {
    console.error('⚠️ Telegram webhook setup failed; the API will continue running:', error.message);
    const retryTimer = setTimeout(() => {
      void initializeTelegram();
    }, 60_000);
    retryTimer.unref();
  }
};

initializeTelegram();

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
