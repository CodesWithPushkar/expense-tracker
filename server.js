require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo').default || require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
// OLD: const PORT = 3000;
const PORT = process.env.PORT || 3000; // NEW: Lets the cloud decide the port

// --- MONGODB ---
// OLD LINE (Delete this):
// mongoose.connect('mongodb://127.0.0.1:27017/expense_tracker')

// NEW LINE (Paste this):
const mongoURI = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/expense_tracker';

mongoose.connect(mongoURI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- SCHEMAS ---
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const groupSchema = new mongoose.Schema({
    name: String,
    code: { type: String, unique: true },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});
const Group = mongoose.model('Group', groupSchema);

const categorySchema = new mongoose.Schema({
    name: String, icon: String, color: String,
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' }
});
const Category = mongoose.model('Category', categorySchema);

const expenseSchema = new mongoose.Schema({
    description: String,
    amount: Number,
    date: Date,
    categoryName: String,
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
    paidBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    splitBetween: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    lastEditedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});
const Expense = mongoose.model('Expense', expenseSchema);

// --- NEW: ACTIVITY LOG SCHEMA ---
const activityLogSchema = new mongoose.Schema({
    action: String, // "CREATED", "EDITED", "DELETED"
    description: String, // "Deleted 'Pizza' (₹500)"
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Who did it
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
    date: { type: Date, default: Date.now }
});
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// --- PASSPORT ---
passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await User.findOne({ username });
        if (!user) return done(null, false, { message: 'Incorrect username.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Incorrect password.' });
        return done(null, user);
    } catch (err) { return done(err); }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => User.findById(id).then(user => done(null, user)));

// --- MIDDLEWARE ---
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'my_super_secret_key', 
    resave: false, 
    saveUninitialized: false,
    
    // OLD LINE (Delete):
    // store: MongoStore.create({ mongoUrl: 'mongodb://127.0.0.1:27017/expense_tracker' }),

    // NEW LINE (Paste):
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/expense_tracker' }),
    
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 }
}));
app.use(passport.initialize());
app.use(passport.session());
const ensureAuth = (req, res, next) => req.isAuthenticated() ? next() : res.status(401).json({ error: 'Not authorized' });

// --- AUTH ROUTES ---
app.post('/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (await User.findOne({ username })) return res.status(400).json({ error: 'Taken' });
        const newUser = new User({ username, password: await bcrypt.hash(password, 10) });
        await newUser.save();
        req.login(newUser, err => res.json({ success: true, redirect: '/dashboard.html' }));
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/auth/login', passport.authenticate('local'), (req, res) => res.json({ success: true, redirect: '/dashboard.html' }));
app.get('/auth/logout', (req, res, next) => { req.logout(err => res.redirect('/login.html')); });

// --- API ROUTES ---

async function getGroup(req, res) {
    const groupId = req.query.groupId || req.body.groupId;
    if (!groupId) { res.status(400).json({ error: 'Group ID required' }); return null; }
    const group = await Group.findById(groupId);
    if (!group || !group.members.map(m=>m.toString()).includes(req.user._id.toString())) {
        res.status(403).json({ error: 'Access denied' }); return null;
    }
    return group;
}

app.get('/api/user', ensureAuth, async (req, res) => {
    const groups = await Group.find({ members: req.user._id });
    res.json({ user: { id: req.user._id, username: req.user.username }, groups });
});

app.get('/api/group/members', ensureAuth, async (req, res) => {
    const group = await getGroup(req, res);
    if(group) { await group.populate('members'); res.json(group.members); }
});

app.get('/api/categories', ensureAuth, async (req, res) => {
    const group = await getGroup(req, res);
    if(group) res.json(await Category.find({ group: group._id }));
});

app.post('/api/categories', ensureAuth, async (req, res) => {
    const group = await getGroup(req, res);
    if(group) {
        const newCat = new Category({ ...req.body, group: group._id });
        await newCat.save();
        res.json(newCat);
    }
});

app.delete('/api/categories/:id', ensureAuth, async (req, res) => {
    await Category.findByIdAndDelete(req.params.id); res.status(204).send();
});

// GET EXPENSES
app.get('/api/expenses', ensureAuth, async (req, res) => {
    const group = await getGroup(req, res);
    if(group) {
        const expenses = await Expense.find({ group: group._id })
            .populate('paidBy', 'username')
            .populate('createdBy', 'username')
            .populate('lastEditedBy', 'username')
            .populate('splitBetween', 'username')
            .sort({ date: -1 });
        res.json(expenses);
    }
});

// ADD EXPENSE
app.post('/api/expenses', ensureAuth, async (req, res) => {
    const group = await getGroup(req, res);
    if (!group) return;

    const { description, totalAmount, date, categoryName, payerType, friendId, splitBetween } = req.body;
    let paidById = req.user._id;
    if (payerType === 'friend' && friendId) paidById = friendId;
    let finalSplit = splitBetween || group.members;

    const newExpense = new Expense({
        description, amount: totalAmount, date: new Date(date), categoryName,
        group: group._id, paidBy: paidById, splitBetween: finalSplit, createdBy: req.user._id
    });
    await newExpense.save();

    // LOG ACTIVITY
    await new ActivityLog({
        action: 'CREATED',
        description: `Added '${description}' (₹${totalAmount})`,
        user: req.user._id,
        group: group._id
    }).save();

    res.status(201).json({ newExpense });
});

// EDIT EXPENSE
app.put('/api/expenses/:id', ensureAuth, async (req, res) => {
    // We fetch the OLD expense first to log what changed
    const oldExpense = await Expense.findById(req.params.id);
    if (!oldExpense) return res.status(404).send();

    const { description, totalAmount, date, categoryName, payerType, friendId, splitBetween, groupId } = req.body;
    
    // Check group permission manually since we need to look up expense first
    // (For simplicity assuming user is allowed if they are logged in and in the group passed)
    
    const updateData = {
        description, amount: totalAmount, date: new Date(date), categoryName,
        paidBy: req.user._id, splitBetween: splitBetween, lastEditedBy: req.user._id
    };

    const updatedExpense = await Expense.findByIdAndUpdate(req.params.id, updateData, { new: true });

    // LOG ACTIVITY
    let changeDesc = `Edited '${oldExpense.description}'`;
    if (oldExpense.amount !== totalAmount) changeDesc += ` - Amount changed from ₹${oldExpense.amount} to ₹${totalAmount}`;
    
    await new ActivityLog({
        action: 'EDITED',
        description: changeDesc,
        user: req.user._id,
        group: groupId // passed from frontend
    }).save();

    res.json(updatedExpense);
});

// DELETE EXPENSE
app.delete('/api/expenses/:id', ensureAuth, async (req, res) => {
    const expense = await Expense.findById(req.params.id);
    if (expense) {
        await Expense.findByIdAndDelete(req.params.id);

        // LOG ACTIVITY
        await new ActivityLog({
            action: 'DELETED',
            description: `Deleted '${expense.description}' (₹${expense.amount})`,
            user: req.user._id,
            group: expense.group
        }).save();
    }
    res.status(204).send();
});

// NEW: GET HISTORY LOGS
app.get('/api/history', ensureAuth, async (req, res) => {
    const group = await getGroup(req, res);
    if(group) {
        const logs = await ActivityLog.find({ group: group._id })
            .populate('user', 'username')
            .sort({ date: -1 })
            .limit(50); // Get last 50 actions
        res.json(logs);
    }
});

// GROUPS
app.post('/api/groups/join', ensureAuth, async (req, res) => {
    const { groupCode, groupName, action } = req.body;
    if (action === 'create') {
        if (await Group.findOne({ code: groupCode })) return res.status(400).json({ error: 'Code taken' });
        const newGroup = await new Group({ name: groupName, code: groupCode, members: [req.user._id] }).save();
        await Category.insertMany([
            { name: 'Food', icon: 'ph-pizza', color: 'text-orange-500', group: newGroup._id },
            { name: 'Travel', icon: 'ph-airplane', color: 'text-blue-500', group: newGroup._id }
        ]);
        return res.json(newGroup);
    } else if (action === 'join') {
        const group = await Group.findOne({ code: groupCode });
        if (!group) return res.status(404).json({ error: 'Not found' });
        if (!group.members.includes(req.user._id)) { group.members.push(req.user._id); await group.save(); }
        return res.json(group);
    }
});

// PAGES
app.get('/dashboard.html', ensureAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/reports.html', ensureAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'reports.html')));
app.get('/categories.html', ensureAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'categories.html')));
app.get('/history.html', ensureAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'history.html'))); // NEW PAGE
app.get('/', (req, res) => req.isAuthenticated() ? res.redirect('/dashboard.html') : res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));