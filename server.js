require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// === DB CONNECT ===
const mongoURI = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/expense_tracker';
mongoose.connect(mongoURI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// === MODELS ===
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    isBanned: { type: Boolean, default: false }
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
    consumedQuantity: { type: Number, default: 0 }
});
const Expense = mongoose.model('Expense', expenseSchema);

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

// === PASSPORT ===
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

// === HELPERS ===
const ensureAuth = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ error: "Not Authorized" });
};
const ensureAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.isAdmin) return next();
    res.status(403).json({ error: "Admins Only" });
};

// === AUTH ROUTES ===

// 1. GET USER INFO (Used by AuthContext)
app.get('/api/user', (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ user: null });
    // Find User's Group
    Group.findOne({ members: req.user._id }).then(group => {
        res.json({ 
            user: {
                ...req.user.toObject(),
                groupCode: group ? group.groupCode : null
            } 
        });
    });
});

// 2. LOGIN
app.post('/auth/login', passport.authenticate('local'), (req, res) => {
    res.json({ success: true, user: req.user });
});

// 3. LOGOUT
app.post('/auth/logout', (req, res) => {
    req.logout(() => { res.json({ success: true }); });
});

// 4. REGISTER + CREATE GROUP
app.post('/auth/register-group', async (req, res) => {
    const { username, password, groupCode } = req.body;
    try {
        if (await User.findOne({ username })) return res.status(400).json({ error: "Username taken" });
        if (await Group.findOne({ groupCode })) return res.status(400).json({ error: "Group exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, isAdmin: true });
        await newUser.save();

        const newGroup = new Group({ 
            name: groupCode + "'s House", groupCode, members: [newUser._id] 
        });
        await newGroup.save();

        req.login(newUser, (err) => res.json({ success: true, user: newUser }));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. REGISTER + JOIN GROUP
app.post('/auth/join-group', async (req, res) => {
    const { username, password, groupCode } = req.body;
    try {
        if (await User.findOne({ username })) return res.status(400).json({ error: "Username taken" });
        const group = await Group.findOne({ groupCode });
        if (!group) return res.status(404).json({ error: "Group not found" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, isAdmin: false });
        await newUser.save();

        if (group.isRestricted) {
            group.pendingMembers.push(newUser._id);
            await group.save();
            return res.json({ success: true, msg: "Approval Pending" });
        }

        group.members.push(newUser._id);
        await group.save();
        req.login(newUser, (err) => res.json({ success: true, user: newUser }));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// === API ROUTES ===

// GET EXPENSES
app.get('/api/expenses', ensureAuth, async (req, res) => {
    // 1. Find user's group
    const group = await Group.findOne({ members: req.user._id });
    if (!group) return res.json([]);

    // 2. Find expenses for that group
    const expenses = await Expense.find({ groupCode: group.groupCode })
        .populate('paidBy', 'username')
        .sort({ date: -1 });
    res.json(expenses);
});

// POST EXPENSE
app.post('/api/expenses', ensureAuth, async (req, res) => {
    const group = await Group.findOne({ members: req.user._id });
    if (!group) return res.status(400).json({ error: "No Group" });

    const newExpense = new Expense({
        ...req.body,
        paidBy: req.user._id,
        groupCode: group.groupCode
    });
    await newExpense.save();
    res.json(newExpense);
});

// === ADMIN ROUTES ===

// GET USERS (For User Management Screen)
app.get('/api/group/members', ensureAuth, async (req, res) => {
    const group = await Group.findOne({ members: req.user._id }).populate('members', 'username isAdmin isBanned');
    res.json(group ? group.members : []);
});

// BAN USER
app.post('/api/admin/ban-user', ensureAdmin, async (req, res) => {
    await User.findByIdAndUpdate(req.body.userId, { isBanned: true });
    res.json({ success: true });
});

// RESET PASSWORD
app.post('/api/admin/reset-password', ensureAdmin, async (req, res) => {
    const hashed = await bcrypt.hash(req.body.newPassword, 10);
    await User.findByIdAndUpdate(req.body.userId, { password: hashed });
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));