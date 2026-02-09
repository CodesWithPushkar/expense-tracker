require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo').default || require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const cors = require('cors'); // Added for App communication

const app = express();
const PORT = process.env.PORT || 3000;

// === DATABASE CONNECTION ===
const mongoURI = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/expense_tracker';
mongoose.connect(mongoURI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// ==========================================
// 1. UPDATED SCHEMAS (Admin, Apples, etc.)
// ==========================================

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false }, // 🔧 God Mode
    isBanned: { type: Boolean, default: false } // 🚫 Ban Hammer
});
const User = mongoose.model('User', userSchema);

const groupSchema = new mongoose.Schema({
    name: String,
    groupCode: { type: String, unique: true, required: true },
    isRestricted: { type: Boolean, default: false }, // 🔒 Port 1008 logic
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    pendingMembers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] // ⏳ Waiting for approval
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
    date: { type: Date, default: Date.now },
    categoryName: String,
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
    paidBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    splitBetween: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    
    // 🍎 THE APPLE FEATURE (Inventory)
    isConsumable: { type: Boolean, default: false }, 
    totalQuantity: { type: Number, default: 1 },     // Bought 5 Apples
    consumedQuantity: { type: Number, default: 0 }   // Ate 2 Apples
});
const Expense = mongoose.model('Expense', expenseSchema);

const activityLogSchema = new mongoose.Schema({
    action: String,
    description: String,
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
    date: { type: Date, default: Date.now }
});
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// ==========================================
// 2. MIDDLEWARE & AUTH CONFIG
// ==========================================

// Enable CORS so your Mobile App can talk to this Server
app.use(cors({
    origin: true, // Allow all origins (for mobile app testing)
    credentials: true
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'super_secret_key_change_this',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoURI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 } // 30 Days
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport Logic
passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await User.findOne({ username });
        if (!user) return done(null, false, { message: 'User not found' });
        if (user.isBanned) return done(null, false, { message: '🚫 You are BANNED.' });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Incorrect password' });
        
        return done(null, user);
    } catch (err) { return done(err); }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => User.findById(id).then(user => done(null, user)));

// Middleware to check if logged in
const ensureAuth = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ error: 'Not authorized' });
};

// ==========================================
// 3. AUTH ROUTES (Smart Registration)
// ==========================================

// Register & CREATE Group (Admin)
app.post('/auth/register-group', async (req, res) => {
    const { username, password, groupCode } = req.body;
    try {
        if (!username || !password || !groupCode) return res.status(400).json({ error: "Missing fields" });
        if (await User.findOne({ username })) return res.status(400).json({ error: "Username taken" });
        if (await Group.findOne({ groupCode })) return res.status(400).json({ error: "Group Code exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, isAdmin: true });
        await newUser.save();

        const newGroup = new Group({ 
            name: groupCode + "'s House", 
            groupCode, 
            members: [newUser._id],
            isRestricted: false // Default open, can change later
        });
        await newGroup.save();

        req.login(newUser, (err) => {
            if (err) return res.status(500).json({ error: "Login failed" });
            res.json({ success: true, user: newUser, group: newGroup });
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Register & JOIN Group (Member)
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
            return res.json({ success: true, msg: "Request sent to Admin!" });
        } else {
            group.members.push(newUser._id);
            await group.save();
            req.login(newUser, (err) => {
                if (err) return res.status(500).json({ error: "Login failed" });
                res.json({ success: true, user: newUser, group });
            });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/login', passport.authenticate('local'), (req, res) => res.json({ success: true, user: req.user }));
app.post('/auth/logout', (req, res) => { req.logout(() => res.json({ success: true })); });

app.get('/api/user', ensureAuth, (req, res) => res.json({ user: req.user }));

// ==========================================
// 4. CORE API ROUTES
// ==========================================

// Get Expenses
app.get('/api/expenses', ensureAuth, async (req, res) => {
    // Find groups the user is in
    const groups = await Group.find({ members: req.user._id });
    const groupIds = groups.map(g => g._id);

    const expenses = await Expense.find({ group: { $in: groupIds } })
        .populate('paidBy', 'username')
        .sort({ date: -1 });
    res.json(expenses);
});

// Create Expense (Handles Apples/Inventory too)
app.post('/api/expenses', ensureAuth, async (req, res) => {
    const { description, amount, groupCode, isConsumable, totalQuantity } = req.body;
    
    const group = await Group.findOne({ groupCode, members: req.user._id });
    if (!group) return res.status(403).json({ error: "Group not found or Access Denied" });

    const newExpense = new Expense({
        description, 
        amount, 
        group: group._id, 
        paidBy: req.user._id,
        splitBetween: group.members,
        isConsumable: isConsumable || false,
        totalQuantity: totalQuantity || 1,
        consumedQuantity: 0
    });
    await newExpense.save();
    
    // Log it
    await new ActivityLog({ action: 'CREATED', description: `Added ${description}`, user: req.user._id, group: group._id }).save();
    
    res.json(newExpense);
});

// 🍎 CONSUME ITEM (Eat an Apple)
app.post('/api/expenses/consume/:id', ensureAuth, async (req, res) => {
    const expense = await Expense.findById(req.params.id);
    if (!expense || !expense.isConsumable) return res.status(400).json({ error: "Not a consumable item" });

    if (expense.consumedQuantity < expense.totalQuantity) {
        expense.consumedQuantity += 1;
        await expense.save();
        
        await new ActivityLog({ 
            action: 'CONSUMED', 
            description: `Ate 1 ${expense.description} (${expense.totalQuantity - expense.consumedQuantity} left)`, 
            user: req.user._id, 
            group: expense.group 
        }).save();
        
        return res.json({ success: true, expense });
    } else {
        return res.status(400).json({ error: "None left!" });
    }
});

// ==========================================
// 5. ADMIN ROUTES (The "God Mode")
// ==========================================

const ensureAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.isAdmin) return next();
    res.status(403).json({ error: "Admins Only" });
};

// Toggle "Port 1008" Mode (Restricted Access)
app.post('/api/admin/toggle-restriction', ensureAdmin, async (req, res) => {
    const { groupCode, restricted } = req.body;
    const group = await Group.findOneAndUpdate({ groupCode }, { isRestricted: restricted }, { new: true });
    res.json(group);
});

// Approve Pending Member
app.post('/api/admin/approve-user', ensureAdmin, async (req, res) => {
    const { userId, groupCode } = req.body;
    const group = await Group.findOne({ groupCode });
    
    group.pendingMembers = group.pendingMembers.filter(id => id.toString() !== userId);
    group.members.push(userId);
    await group.save();
    
    res.json({ success: true, msg: "User Approved" });
});

// Ban User
app.post('/api/admin/ban-user', ensureAdmin, async (req, res) => {
    const { userId } = req.body;
    await User.findByIdAndUpdate(userId, { isBanned: true });
    res.json({ success: true, msg: "User Banned" });
});

// Force Password Reset
app.post('/api/admin/reset-password', ensureAdmin, async (req, res) => {
    const { userId, newPassword } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(userId, { password: hashedPassword });
    res.json({ success: true, msg: "Password Reset" });
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));