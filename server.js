require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo').default || require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

const mongoURI = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/expense_tracker';
mongoose.connect(mongoURI).then(async () => {
    console.log('✅ Connected to MongoDB');
    try { await mongoose.connection.collection('groups').dropIndex('code_1'); } catch (e) {}
}).catch(err => console.error('❌ MongoDB Connection Error:', err));

// === MODELS ===
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    isBanned: { type: Boolean, default: false },
    activeGroup: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
    joinedGroups: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Group' }]
});
const User = mongoose.model('User', userSchema);

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
    category: String,
    date: { type: Date, default: Date.now },
    paidBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    groupCode: String,
    isConsumable: { type: Boolean, default: false },
    totalQuantity: { type: Number, default: 1 },
    consumedQuantity: { type: Number, default: 0 },
    splitBetween: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});
const Expense = mongoose.model('Expense', expenseSchema);

// 📜 HISTORY LOG
const historySchema = new mongoose.Schema({
    groupCode: String,
    action: String,
    message: String,
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    date: { type: Date, default: Date.now }
});
const History = mongoose.model('History', historySchema);

// === MIDDLEWARE ===
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'super_secret_key_123',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoURI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } 
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await User.findOne({ username });
        if (!user) return done(null, false, { message: 'User not found' });
        if (user.isBanned) return done(null, false, { message: 'You are BANNED.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Incorrect password' });
        return done(null, user);
    } catch (err) { return done(err); }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { const user = await User.findById(id); done(null, user); } catch (e) { done(e); }
});

const ensureAuth = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ error: "Not Authorized" });
};
const ensureAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.isAdmin) return next();
    res.status(403).json({ error: "Admins Only" });
};

// === ROUTES ===

app.get('/api/user', (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ user: null });
    Group.findById(req.user.activeGroup).then(group => {
        res.json({ user: { ...req.user.toObject(), groupCode: group ? group.groupCode : null } });
    });
});

// SELF-HEALING LOGIN (Fixes old users)
app.post('/auth/login', passport.authenticate('local'), async (req, res) => {
    if (!req.user.activeGroup && req.user.joinedGroups && req.user.joinedGroups.length > 0) {
        req.user.activeGroup = req.user.joinedGroups[0];
        await req.user.save();
    } 
    // Fallback for very old users without joinedGroups
    else if (!req.user.activeGroup) {
        const group = await Group.findOne({ members: req.user._id });
        if (group) {
            req.user.joinedGroups = [group._id];
            req.user.activeGroup = group._id;
            await req.user.save();
        }
    }
    res.json({ success: true, user: req.user });
});

app.post('/auth/logout', (req, res) => req.logout(() => res.json({ success: true })));

// REGISTER NEW USER + GROUP
app.post('/auth/register-group', async (req, res) => {
    const { username, password, groupCode, adminSecret } = req.body;
    try {
        if (!username || !password || !groupCode) return res.status(400).json({ error: "Missing fields" });
        if (await User.findOne({ username })) return res.status(400).json({ error: "Username taken" });
        if (await Group.findOne({ groupCode })) return res.status(400).json({ error: "Group exists" });

        const isAdmin = (adminSecret === "pushkargod mod");
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, isAdmin });
        
        const newGroup = new Group({ name: groupCode + "'s House", groupCode, members: [newUser._id] });
        await newGroup.save();

        newUser.joinedGroups = [newGroup._id];
        newUser.activeGroup = newGroup._id;
        await newUser.save();

        req.login(newUser, (err) => res.json({ success: true, user: newUser }));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// JOIN FOR NEW USERS (Login Screen)
app.post('/auth/join-group', async (req, res) => {
    const { username, password, groupCode } = req.body;
    try {
        if (await User.findOne({ username })) return res.status(400).json({ error: "Username taken" });
        const group = await Group.findOne({ groupCode });
        if (!group) return res.status(404).json({ error: "Group not found" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, isAdmin: false });
        
        if (group.isRestricted) {
            group.pendingMembers.push(newUser._id);
            await newUser.save();
            await group.save();
            return res.json({ success: true, msg: "Request Sent. Wait for Admin Approval." });
        }

        group.members.push(newUser._id);
        await group.save();
        newUser.joinedGroups = [group._id];
        newUser.activeGroup = group._id;
        await newUser.save();
        req.login(newUser, (err) => res.json({ success: true, user: newUser }));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 🚀 NEW: JOIN EXISTING GROUP (For Logged In Users)
app.post('/api/user/join-existing', ensureAuth, async (req, res) => {
    const { groupCode } = req.body;
    try {
        const group = await Group.findOne({ groupCode });
        if (!group) return res.status(404).json({ error: "Group not found" });

        // Check if already in group
        if (req.user.joinedGroups.includes(group._id)) {
            return res.status(400).json({ error: "You are already in this group!" });
        }

        if (group.isRestricted) {
            if (!group.pendingMembers.includes(req.user._id)) {
                group.pendingMembers.push(req.user._id);
                await group.save();
            }
            return res.json({ success: true, msg: "Request Sent to Admin." });
        }

        // Add to group
        group.members.push(req.user._id);
        await group.save();

        // Add to user
        req.user.joinedGroups.push(group._id);
        req.user.activeGroup = group._id; // Switch immediately
        await req.user.save();

        res.json({ success: true, msg: `Joined ${group.name}!` });
    } catch (e) { res.status(500).json({ error: "Join failed" }); }
});

// SWITCH ACTIVE GROUP
app.post('/api/user/switch-group', ensureAuth, async (req, res) => {
    const { groupId } = req.body;
    const group = await Group.findById(groupId);
    if (!group || !group.members.includes(req.user._id)) {
        return res.status(403).json({ error: "You are not in this group" });
    }
    req.user.activeGroup = groupId;
    await req.user.save();
    res.json({ success: true, groupName: group.name });
});

// GET MY GROUPS
app.get('/api/user/groups', ensureAuth, async (req, res) => {
    await req.user.populate('joinedGroups', 'name groupCode');
    res.json({ groups: req.user.joinedGroups, activeGroupId: req.user.activeGroup });
});

// === EXPENSES ===
app.get('/api/expenses', ensureAuth, async (req, res) => {
    if (!req.user.activeGroup) return res.json([]);
    const group = await Group.findById(req.user.activeGroup);
    const expenses = await Expense.find({ groupCode: group.groupCode }).populate('paidBy', 'username').sort({ date: -1 });
    res.json(expenses);
});

app.post('/api/expenses', ensureAuth, async (req, res) => {
    if (!req.user.activeGroup) return res.status(400).json({ error: "No Active Group" });
    const group = await Group.findById(req.user.activeGroup);
    
    // EDIT
    if (req.body.isEdit) {
        const oldExpense = await Expense.findById(req.body.expenseId);
        if (!oldExpense) return res.status(404).json({error: "Expense not found"});
        const updated = await Expense.findByIdAndUpdate(req.body.expenseId, req.body.newData, { new: true });
        await History.create({
            groupCode: group.groupCode,
            action: 'EDIT',
            message: `edited "${oldExpense.description}" (₹${oldExpense.amount} → ₹${updated.amount})`,
            user: req.user._id
        });
        return res.json({ success: true, msg: "Updated", expense: updated });
    }

    // ADD
    let splitBetween = req.body.splitBetween || [];
    if (splitBetween.length === 0) splitBetween = group.members;

    const newExpense = new Expense({ 
        ...req.body, 
        paidBy: req.user._id, 
        groupCode: group.groupCode,
        splitBetween: splitBetween
    });
    await newExpense.save();

    await History.create({
        groupCode: group.groupCode,
        action: 'ADD',
        message: `added "${newExpense.description}" (₹${newExpense.amount})`,
        user: req.user._id
    });

    res.json(newExpense);
});

// DELETE
app.post('/api/expenses/delete', ensureAuth, async (req, res) => {
    const { expenseId } = req.body;
    const expense = await Expense.findById(expenseId);
    if (!expense) return res.status(404).json({ error: "Not found" });

    const group = await Group.findById(req.user.activeGroup);
    await Expense.findByIdAndDelete(expenseId);

    await History.create({
        groupCode: group.groupCode,
        action: 'DELETE',
        message: `deleted "${expense.description}" (₹${expense.amount})`,
        user: req.user._id
    });

    return res.json({ success: true, msg: "Deleted" });
});

// HISTORY
app.get('/api/group/history', ensureAuth, async (req, res) => {
    if (!req.user.activeGroup) return res.json([]);
    const group = await Group.findById(req.user.activeGroup);
    const logs = await History.find({ groupCode: group.groupCode }).populate('user', 'username').sort({ date: -1 }).limit(50);
    res.json(logs);
});

// CONSUME
app.post('/api/expenses/consume', ensureAuth, async (req, res) => {
    const { expenseId } = req.body;
    const expense = await Expense.findById(expenseId);
    if (expense && expense.consumedQuantity < expense.totalQuantity) {
        expense.consumedQuantity += 1;
        await expense.save();
    }
    res.json({ success: true, expense });
});

// DEBTS
app.get('/api/reports/debts', ensureAuth, async (req, res) => {
    if (!req.user.activeGroup) return res.json([]);
    const group = await Group.findById(req.user.activeGroup).populate('members', 'username');
    const expenses = await Expense.find({ groupCode: group.groupCode });

    let balances = {}; 
    let usernames = {}; 
    group.members.forEach(m => { balances[m._id] = 0; usernames[m._id] = m.username; });

    expenses.forEach(exp => {
        const payerId = exp.paidBy.toString();
        let involved = exp.splitBetween && exp.splitBetween.length > 0 
            ? exp.splitBetween.map(id => id.toString())
            : group.members.map(m => m._id.toString());
        const splitAmount = exp.amount / involved.length;
        if (balances[payerId] !== undefined) balances[payerId] += exp.amount;
        involved.forEach(uid => { if (balances[uid] !== undefined) balances[uid] -= splitAmount; });
    });

    let debtors = [], creditors = [];
    for (const [uid, bal] of Object.entries(balances)) {
        if (bal < -0.01) debtors.push({ id: uid, amount: bal });
        if (bal > 0.01) creditors.push({ id: uid, amount: bal });
    }
    debtors.sort((a, b) => a.amount - b.amount);
    creditors.sort((a, b) => b.amount - a.amount);

    let settlements = [];
    let i = 0, j = 0;
    while (i < debtors.length && j < creditors.length) {
        let debtor = debtors[i], creditor = creditors[j];
        let amount = Math.min(Math.abs(debtor.amount), creditor.amount);
        settlements.push({
            from: usernames[debtor.id] || "Unknown",
            to: usernames[creditor.id] || "Unknown",
            amount: Math.round(amount)
        });
        debtor.amount += amount; creditor.amount -= amount;
        if (Math.abs(debtor.amount) < 0.01) i++;
        if (creditor.amount < 0.01) j++;
    }
    res.json(settlements);
});

// ADMIN
app.get('/api/group/members', ensureAuth, async (req, res) => {
    const group = await Group.findById(req.user.activeGroup).populate('members', 'username isAdmin isBanned');
    res.json(group ? group.members : []);
});

app.get('/api/admin/pending', ensureAdmin, async (req, res) => {
    const group = await Group.findById(req.user.activeGroup).populate('pendingMembers', 'username');
    res.json({ pending: group ? group.pendingMembers : [], isRestricted: group ? group.isRestricted : false });
});

app.post('/api/admin/toggle-lock', ensureAdmin, async (req, res) => {
    const group = await Group.findById(req.user.activeGroup);
    group.isRestricted = !group.isRestricted;
    await group.save();
    res.json({ success: true, isRestricted: group.isRestricted });
});

app.post('/api/admin/approve', ensureAdmin, async (req, res) => {
    const { userId, approve } = req.body;
    const group = await Group.findById(req.user.activeGroup);
    group.pendingMembers = group.pendingMembers.filter(id => id.toString() !== userId);
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
    await User.findByIdAndUpdate(req.body.userId, { isBanned: true });
    res.json({ success: true });
});

app.post('/api/admin/reset-password', ensureAdmin, async (req, res) => {
    const hashed = await bcrypt.hash(req.body.newPassword, 10);
    await User.findByIdAndUpdate(req.body.userId, { password: hashed });
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));