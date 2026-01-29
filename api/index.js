const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { error } = require('console');
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

        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '0.5h' });
        res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



app.get('/api/get_user/:id', async (req, res) => {
    try {
        const [user] = await pool.query('SELECT id, name, email FROM users WHERE id = ?', [req.params.id]);
        res.json(user);
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

// --- SESSION MANAGEMENT ---

app.get('/api/sessions', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM presentation_sessions ORDER BY session_date DESC');
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/sessions', authenticateToken, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin only" });
    const { round_id, session_date, topic } = req.body;
    try {
        const [result] = await pool.execute(
            'INSERT INTO presentation_sessions (round_id, session_date, topic) VALUES (?, ?, ?)',
            [round_id, session_date, topic]
        );
        res.json({ message: "Monday session created", sessionId: result.insertId });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- DASHBOARD ---
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const [activeRound] = await pool.query('SELECT id, name FROM rounds_list WHERE is_active = TRUE LIMIT 1');
        const roundId = activeRound[0]?.id || 0;

        const [groups] = await pool.query('SELECT COUNT(*) as count FROM groups_list');
        const [avg] = await pool.query('SELECT AVG(average_score) as globalAvg FROM evaluations WHERE round_id = ?', [roundId]);

        // Trend Chart: Avg Score by Day of Week (0-6)
        const [trends] = await pool.query(`
            SELECT WEEKDAY(created_at) as day, AVG(average_score) as avgScore
            FROM evaluations 
            WHERE round_id = ? 
            GROUP BY day 
            ORDER BY day ASC`, [roundId]
        );
        // Map to 7 days
        const trendData = Array(7).fill(0);
        trends.forEach(t => trendData[t.day] = parseFloat(t.avgScore).toFixed(1));

        // Sparkline: Last 10 evaluations scores
        const [spark] = await pool.query('SELECT total_score FROM evaluations WHERE round_id = ? ORDER BY created_at DESC LIMIT 10', [roundId]);
        const sparklineData = spark.map(s => parseFloat(s.total_score));

        // Total evaluations count for the round
        const [evalCount] = await pool.query('SELECT COUNT(*) as count FROM evaluations WHERE round_id = ?', [roundId]);

        res.json({
            currentRoundName: activeRound[0]?.name || "None",
            totalGroups: groups[0].count,
            totalEvaluations: evalCount[0].count,
            globalAverage: parseFloat(avg[0].globalAvg || 0).toFixed(2),
            trendData,
            sparklineData: sparklineData.reverse() // Show oldest to newest
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- USER & GROUP MANAGEMENT ---

app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT u.id, u.name, u.email, u.role, u.created_at, gm.group_id
            FROM users u
            LEFT JOIN group_members gm ON u.id = gm.user_id
        `;
        const [rows] = await pool.query(query);
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

app.get('/api/groups/:id', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM groups_list WHERE id = ?', [req.params.id]);
        if (rows.length === 0) return res.status(404).json({ error: "Group not found" });
        res.json(rows[0]);
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

    if (!group_id || !user_id) {
        return res.status(400).json({ error: "Missing IDs" });
    }

    try {
        await pool.execute('DELETE FROM group_members WHERE user_id = ?', [user_id]);

        await pool.execute(
            'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
            [group_id, user_id]
        );

        res.json({ message: "User moved to the team successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error during reassignment" });
    }
});

app.get('/api/groups/:id/members', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT u.id, u.name, u.email 
            FROM users u 
            JOIN group_members gm ON u.id = gm.user_id 
            WHERE gm.group_id = ?`;
        const [rows] = await pool.query(query, [req.params.id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ADVANCED RANKINGS ---

app.get('/api/rankings/groups', authenticateToken, async (req, res) => {
    try {
        const [activeRound] = await pool.query('SELECT id FROM rounds_list WHERE is_active = TRUE LIMIT 1');
        const roundId = activeRound[0]?.id || 0;

        // Complex JOIN to get group members and their latest scores
        const query = `
            SELECT 
                g.id as groupId, g.name as groupName,
                MIN(e.total_score) as minScore,
                MAX(e.total_score) as maxScore,
                (MAX(e.total_score) - MIN(e.total_score)) as performanceGap,
                AVG(e.total_score) as groupAvg
            FROM groups_list g
            JOIN group_members gm ON g.id = gm.group_id
            JOIN evaluations e ON gm.user_id = e.member_id
            WHERE e.round_id = ?
            GROUP BY g.id
            ORDER BY minScore DESC`;

        const [rankings] = await pool.query(query, [roundId]);
        res.json(rankings);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/rankings/members', authenticateToken, async (req, res) => {
    try {
        const [activeRound] = await pool.query('SELECT id FROM rounds_list WHERE is_active = TRUE LIMIT 1');
        const roundId = activeRound[0]?.id || 0;

        const query = `
            SELECT u.id, u.name, u.role, SUM(e.total_score) as cumulativeScore, COUNT(e.id) as sessionsCount
            FROM users u
            JOIN evaluations e ON u.id = e.member_id
            WHERE e.round_id = ?
            GROUP BY u.id
            ORDER BY cumulativeScore DESC
            LIMIT 10`;

        const [leaderboard] = await pool.query(query, [roundId]);
        res.json(leaderboard);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- SCORING (EVALUATIONS) ---

app.post('/api/evaluations', authenticateToken, async (req, res) => {
    const {
        member_id, group_id, session_id,
        s_style, s_content, s_clarity, s_timing,
        s_wow, s_clear_res, s_acc_res, s_con_res,
        strengths, improvements
    } = req.body;

    try {
        const [activeRounds] = await pool.query('SELECT id FROM rounds_list WHERE is_active = TRUE LIMIT 1');
        if (activeRounds.length === 0) return res.status(400).json({ error: "No active round set by Admin" });
        const round_id = activeRounds[0].id;

        // Auto-detect session if not provided
        let finalSessionId = session_id;
        if (!finalSessionId) {
            const [recentSession] = await pool.query(
                'SELECT id FROM presentation_sessions WHERE round_id = ? AND session_date <= CURDATE() ORDER BY session_date DESC LIMIT 1',
                [round_id]
            );
            if (recentSession.length > 0) finalSessionId = recentSession[0].id;
        }

        const scores = [s_style, s_content, s_clarity, s_timing, s_wow, s_clear_res, s_acc_res, s_con_res].map(s => parseFloat(s) || 0);
        const total = scores.reduce((a, b) => a + b, 0);
        const avg = total / scores.length;

        const query = `
            INSERT INTO evaluations 
            (evaluator_id, member_id, group_id, round_id, session_id,
             score_slide_style, score_content, score_clarity, score_timing, 
             score_wow_factor, score_clear_response, score_accurate_response, score_conciseness,
             average_score, total_score, strengths, improvements) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        await pool.execute(query, [req.user.id, member_id, group_id, round_id, finalSessionId || null, ...scores, avg, total, strengths, improvements]);
        res.json({ message: "Evaluation saved", total: total.toFixed(2), average: avg.toFixed(2) });

    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- EXPORTS ---
if (process.env.NODE_ENV !== 'production') {
    app.listen(3000, () => console.log(`Server at http://localhost:3000`));
}
module.exports = app;
