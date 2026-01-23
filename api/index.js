const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- DATABASE CONFIGURATION ---
const pool = mysql.createPool({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
    port: process.env.MYSQL_PORT || 3306,
    ssl: { rejectUnauthorized: true },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'scoreflow_secure_secret_xyz';

// --- SECURITY MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Access denied. Token missing." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or expired token." });
        req.user = user;
        next();
    });
};

// --- AUTHENTICATION ---

app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, role || 'MEMBER']
        );
        res.status(201).json({ message: "User created", userId: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: "Email already exists" });
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ROUND / ROTATION MANAGEMENT ---

app.get('/api/rounds', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM rounds_list ORDER BY created_at DESC');
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/rounds', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin only" });
    const { name } = req.body;
    try {
        await pool.execute('INSERT INTO rounds_list (name) VALUES (?)', [name]);
        res.json({ message: "Round created" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/rounds/:id/activate', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin only" });
    try {
        await pool.execute('UPDATE rounds_list SET is_active = FALSE');
        await pool.execute('UPDATE rounds_list SET is_active = TRUE WHERE id = ?', [req.params.id]);
        res.json({ message: "Round activated" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- DASHBOARD ---

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const [activeRound] = await pool.query('SELECT id, name FROM rounds_list WHERE is_active = TRUE LIMIT 1');
        const roundId = activeRound[0]?.id || 0;

        const [groups] = await pool.query('SELECT COUNT(*) as count FROM groups_list');
        const [avg] = await pool.query('SELECT AVG(average_score) as globalAvg FROM evaluations WHERE round_id = ?', [roundId]);
        
        res.json({
            currentRoundName: activeRound[0]?.name || "None",
            totalGroups: groups[0].count,
            globalAverage: parseFloat(avg[0].globalAvg || 0).toFixed(2)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- USER & GROUP MANAGEMENT ---

app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, name, email, role, created_at FROM users');
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const [user] = await pool.query('SELECT id, name, email, role FROM users WHERE id = ?', [req.params.id]);
        const [history] = await pool.query(`
            SELECT e.*, g.name as group_name, r.name as round_name
            FROM evaluations e 
            JOIN groups_list g ON e.group_id = g.id 
            JOIN rounds_list r ON e.round_id = r.id
            WHERE e.member_id = ? 
            ORDER BY e.created_at DESC`, [req.params.id]);
        res.json({ user: user[0], evaluations: history });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/groups', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM groups_list');
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/groups', authenticateToken, async (req, res) => {
    const { name, description } = req.body;
    try {
        const [result] = await pool.execute('INSERT INTO groups_list (name, description) VALUES (?, ?)', [name, description]);
        res.json({ message: "Group created", groupId: result.insertId });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/groups/members', authenticateToken, async (req, res) => {
    const { group_id, user_id } = req.body;
    try {
        await pool.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', [group_id, user_id]);
        res.json({ message: "Member assigned" });
    } catch (err) { res.status(400).json({ error: "User already in group or invalid ID" }); }
});

// --- SCORING (EVALUATIONS) ---

app.post('/api/evaluations', authenticateToken, async (req, res) => {
    const { 
        member_id, group_id, 
        s_style, s_content, s_clarity, s_timing, 
        s_wow, s_clear_res, s_acc_res, s_con_res,
        strengths, improvements 
    } = req.body;

    try {
        // Find active round
        const [activeRounds] = await pool.query('SELECT id FROM rounds_list WHERE is_active = TRUE LIMIT 1');
        if (activeRounds.length === 0) return res.status(400).json({ error: "No active round set by Admin" });
        const round_id = activeRounds[0].id;

        // Math
        const scores = [s_style, s_content, s_clarity, s_timing, s_wow, s_clear_res, s_acc_res, s_con_res].map(s => parseFloat(s) || 0);
        const avg = scores.reduce((a, b) => a + b, 0) / scores.length;

        const query = `
            INSERT INTO evaluations 
            (evaluator_id, member_id, group_id, round_id, 
             score_slide_style, score_content, score_clarity, score_timing, 
             score_wow_factor, score_clear_response, score_accurate_response, score_conciseness,
             average_score, strengths, improvements) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        
        await pool.execute(query, [req.user.id, member_id, group_id, round_id, ...scores, avg, strengths, improvements]);
        res.json({ message: "Evaluation saved", average: avg.toFixed(2) });

    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- EXPORTS ---
if (process.env.NODE_ENV !== 'production') {
    app.listen(3000, () => console.log(`Server at http://localhost:3000`));
}
module.exports = app;