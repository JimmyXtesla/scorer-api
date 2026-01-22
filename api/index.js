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
    ssl: { rejectUnauthorized: true }, // Required for Hostinger/Aiven/Railway
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'scoreflow_ultra_secret_88';

// --- SECURITY MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Access denied. Token missing." });

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(403).json({ error: "Invalid or expired token." });
    }
};

// --- AUTHENTICATION ENDPOINTS ---

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
        res.json({ token, user: { id: user.id, name: user.name, role: user.role, email: user.email } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- DASHBOARD ENDPOINTS ---

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const [groups] = await pool.query('SELECT COUNT(*) as count FROM groups_list');
        const [users] = await pool.query('SELECT COUNT(*) as count FROM users');
        const [avg] = await pool.query('SELECT AVG(average_score) as globalAvg FROM evaluations');
        
        res.json({
            totalGroups: groups[0].count,
            totalUsers: users[0].count,
            globalAverage: parseFloat(avg[0].globalAvg || 0).toFixed(2)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- USER ENDPOINTS ---

app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, name, email, role, created_at FROM users');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const [user] = await pool.query('SELECT id, name, email, role FROM users WHERE id = ?', [req.params.id]);
        const [history] = await pool.query(`
            SELECT e.*, g.name as group_name 
            FROM evaluations e 
            JOIN groups_list g ON e.group_id = g.id 
            WHERE e.member_id = ? 
            ORDER BY e.created_at DESC`, [req.params.id]);
        res.json({ user: user[0], evaluations: history });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- GROUP ENDPOINTS ---

app.get('/api/groups', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM groups_list');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/groups', authenticateToken, async (req, res) => {
    if (req.user.role === 'MEMBER') return res.status(403).json({ error: "Unauthorized" });
    const { name, description } = req.body;
    try {
        const [result] = await pool.execute('INSERT INTO groups_list (name, description) VALUES (?, ?)', [name, description]);
        res.json({ message: "Group created", groupId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- EVALUATION (SCORING) ENDPOINT ---

app.post('/api/evaluations', authenticateToken, async (req, res) => {
    const { 
        member_id, group_id, 
        s_style, s_content, s_clarity, s_timing, 
        s_wow, s_clear_res, s_acc_res, s_con_res,
        strengths, improvements 
    } = req.body;

    const evaluator_id = req.user.id; // Taken from JWT token for security

    // Math: Average of the 8 criteria provided in your image
    const scores = [
        s_style ?? 0, s_content ?? 0, s_clarity ?? 0, s_timing ?? 0, 
        s_wow ?? 0, s_clear_res ?? 0, s_acc_res ?? 0, s_con_res ?? 0
    ].map(s => parseFloat(s));
    
    const sum = scores.reduce((a, b) => a + b, 0);
    const avg = sum / scores.length;

    try {
        const query = `
            INSERT INTO evaluations 
            (evaluator_id, member_id, group_id, 
             score_slide_style, score_content, score_clarity, score_timing, 
             score_wow_factor, score_clear_response, score_accurate_response, score_conciseness,
             average_score, strengths, improvements) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        
        const values = [
            evaluator_id, member_id, group_id, 
            ...scores, avg, strengths ?? null, improvements ?? null
        ];

        await pool.execute(query, values);
        res.json({ message: "Evaluation submitted successfully", average: avg.toFixed(2) });
    } catch (err) {
        console.error("Evaluation Error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// --- SERVER LIFECYCLE ---

// Local development listener
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 Server ready at http://localhost:${PORT}`));
}

// Export for Vercel
module.exports = app;
