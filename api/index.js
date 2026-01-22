const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';

require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// MySQL Connection Pool
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


// Check for Auth
const token = localStorage.getItem('token');
const user = JSON.parse(localStorage.getItem('user'));

if (!token) {
    window.location.href = 'auth.html';
}

// Display user name in the sidebar
document.addEventListener('DOMContentLoaded', () => {
    if(user) {
        document.getElementById('sidebar-username').innerText = user.name;
    }
});

// Logout function
function logout() {
    localStorage.clear();
    window.location.href = 'auth.html';
}

// Get summary stats
app.get('/api/dashboard/stats', async (req, res) => {
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

// Get all users
app.get('/api/users', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, name, email, role, avatar_url, created_at FROM users ORDER BY name ASC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create new user
app.post('/api/users', async (req, res) => {
    const { name, email, role, password } = req.body;
    try {
        const [result] = await pool.execute(
            'INSERT INTO users (name, email, role, password) VALUES (?, ?, ?, ?)',
            [name, email, role || 'MEMBER', password || 'default123']
        );
        res.json({ message: "User created", userId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get individual performance (Profile Page)
app.get('/api/users/:id', async (req, res) => {
    try {
        const [user] = await pool.query('SELECT id, name, email, role, avatar_url FROM users WHERE id = ?', [req.params.id]);
        const [history] = await pool.query(`
            SELECT e.*, g.name as group_name 
            FROM evaluations e 
            JOIN groups_list g ON e.group_id = g.id 
            WHERE e.member_id = ? 
            ORDER BY e.created_at DESC`, [req.params.id]);
        
        if (user.length === 0) return res.status(404).json({ error: "User not found" });
        res.json({ user: user[0], evaluations: history });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- GROUP ENDPOINTS ---

// Get all groups with member counts
app.get('/api/groups', async (req, res) => {
    try {
        const query = `
            SELECT g.*, COUNT(gm.user_id) as memberCount 
            FROM groups_list g 
            LEFT JOIN group_members gm ON g.id = gm.group_id 
            GROUP BY g.id`;
        const [rows] = await pool.query(query);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get members of a specific group
app.get('/api/groups/:id/members', async (req, res) => {
    try {
        const query = `
            SELECT u.id, u.name, u.email, u.avatar_url 
            FROM users u 
            JOIN group_members gm ON u.id = gm.user_id 
            WHERE gm.group_id = ?`;
        const [rows] = await pool.query(query, [req.params.id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add member to group
app.post('/api/groups/members', async (req, res) => {
    const { group_id, user_id } = req.body;
    try {
        await pool.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', [group_id, user_id]);
        res.json({ message: "Member added to group" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- EVALUATION / SCORING ENDPOINTS ---

// Submit a score
app.post('/api/evaluations', async (req, res) => {
    const { evaluator_id, member_id, group_id, s1, s2, s3, strengths, improvements } = req.body;
    
    // Server-side calculation of average for data integrity
    const avg = (parseFloat(s1) + parseFloat(s2) + parseFloat(s3)) / 3;

    try {
        const query = `
            INSERT INTO evaluations 
            (evaluator_id, member_id, group_id, score_accuracy, score_speed, score_teamwork, average_score, strengths, improvements) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        
        const [result] = await pool.execute(query, [
            evaluator_id, member_id, group_id, s1, s2, s3, avg, strengths, improvements
        ]);
        
        res.json({ 
            message: "Evaluation submitted", 
            evaluationId: result.insertId,
            calculatedAverage: avg.toFixed(2)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Export for Vercel
module.exports = app;
