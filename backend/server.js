const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'attendance_db',
    password: process.env.DB_PASSWORD || 'newpassword',
    port: 5432,
});

const JWT_SECRET = process.env.JWT_SECRET || 'supreme_secret_999';
const generate6DigitToken = () => Math.floor(100000 + Math.random() * 900000).toString();

// --- AUTH MIDDLEWARES ---
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "No Token" });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        next();
    });
};

const authorize = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Access Denied" });
    next();
};
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: "User not found" });

    const valid = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: "Wrong password" });

    // const token = jwt.sign({ id: user.rows[0].id, role: user.rows[0].role,student_id: user.rows[0].student_id }, JWT_SECRET);
    const token = jwt.sign(
        { 
          id: user.rows[0].id, 
          role: user.rows[0].role,
          student_id: user.rows[0].student_id 
        },
        JWT_SECRET,
        { expiresIn: "2d" }   
      );
      
    res.json({ token, role: user.rows[0].role });
});
// ==========================================
// 1. DEPARTMENT CRUD
// ==========================================
app.post('/api/admin/depts', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, code } = req.body;
    const result = await pool.query('INSERT INTO departments (dept_name, dept_code) VALUES ($1, $2) RETURNING *', [name, code]);
    res.status(201).json(result.rows[0]);
});

app.get('/api/admin/depts', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM departments');
    res.json(result.rows);
});

app.put('/api/admin/depts/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, code } = req.body;
    await pool.query('UPDATE departments SET dept_name = $1, dept_code = $2 WHERE id = $3', [name, code, req.params.id]);
    res.json({ message: "Department Updated" });
});

app.delete('/api/admin/depts/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM departments WHERE id = $1', [req.params.id]);
    res.json({ message: "Department Deleted" });
});

// ==========================================
// 2. BATCH CRUD
// ==========================================
app.post('/api/admin/batches', authenticateToken, authorize(['admin']), async (req, res) => {
    const { dept_id, start_year, end_year, batch_name } = req.body;
    const result = await pool.query('INSERT INTO batches (dept_id, start_year, end_year, batch_name) VALUES ($1,$2,$3,$4) RETURNING *', [dept_id, start_year, end_year, batch_name]);
    res.json(result.rows[0]);
});

app.get('/api/admin/batches', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT b.*, d.dept_code FROM batches b JOIN departments d ON b.dept_id = d.id');
    res.json(result.rows);
});

app.put('/api/admin/batches/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { start_year, end_year, batch_name } = req.body;
    await pool.query('UPDATE batches SET start_year=$1, end_year=$2, batch_name=$3 WHERE id=$4', [start_year, end_year, batch_name, req.params.id]);
    res.json({ message: "Batch Updated" });
});

app.delete('/api/admin/batches/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM batches WHERE id = $1', [req.params.id]);
    res.json({ message: "Batch Deleted" });
});

// ==========================================
// 3. SECTION CRUD
// ==========================================
app.post('/api/admin/sections', authenticateToken, authorize(['admin']), async (req, res) => {
    const { batch_id, section_name } = req.body;
    const result = await pool.query('INSERT INTO sections (batch_id, section_name) VALUES ($1, $2) RETURNING *', [batch_id, section_name]);
    res.json(result.rows[0]);
});

app.get('/api/admin/sections', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT s.*, b.batch_name FROM sections s JOIN batches b ON s.batch_id = b.id');
    res.json(result.rows);
});

app.put('/api/admin/sections/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { section_name } = req.body;
    await pool.query('UPDATE sections SET section_name = $1 WHERE id = $2', [section_name, req.params.id]);
    res.json({ message: "Section Updated" });
});

app.delete('/api/admin/sections/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM sections WHERE id = $1', [req.params.id]);
    res.json({ message: "Section Deleted" });
});


// ==========================================
// 4. FACULTY CRUD (UPDATED)
// ==========================================

// A. GET ALL FACULTY (Even those without accounts)
app.get('/api/admin/faculty', authenticateToken, async (req, res) => {
    try {
        const sql = `
            SELECT 
                f.id as profile_id, 
                f.faculty_name, 
                f.email, 
                f.dept_id, 
                d.dept_code, 
                f.authorization_key, 
                u.id as user_id -- This will be null if no account exists
            FROM faculty_profiles f
            JOIN departments d ON f.dept_id = d.id
            LEFT JOIN users u ON f.user_id = u.id
            ORDER BY f.faculty_name ASC`;
        const result = await pool.query(sql);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// B. STEP 1: CREATE FACULTY PROFILE (Directory Entry Only)
app.post('/api/admin/faculty-profile', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, email, dept_id, auth_key } = req.body;
    try {
        await pool.query(
            'INSERT INTO faculty_profiles (faculty_name, email, dept_id, authorization_key) VALUES ($1, $2, $3, $4)',
            [name, email, dept_id, auth_key]
        );
        res.json({ message: "Faculty Profile Added" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// C. STEP 2: CREATE LOGIN FOR EXISTING PROFILE
app.post('/api/admin/faculty-login', authenticateToken, authorize(['admin']), async (req, res) => {
    const { faculty_profile_id, password } = req.body;
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        // 1. Get Email from Profile
        const profile = await client.query('SELECT email FROM faculty_profiles WHERE id = $1', [faculty_profile_id]);
        if (profile.rows.length === 0) throw new Error("Profile not found");
        const email = profile.rows[0].email;

        // 2. Create User Account
        const hash = await bcrypt.hash(password, 10);
        const userRes = await client.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, \'faculty\') RETURNING id',
            [email, hash]
        );
        const newUserId = userRes.rows[0].id;

        // 3. Link User to Profile
        await client.query(
            'UPDATE faculty_profiles SET user_id = $1 WHERE id = $2',
            [newUserId, faculty_profile_id]
        );

        await client.query('COMMIT');
        res.json({ message: "User account created and linked to faculty profile" });
    } catch (e) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: e.message });
    } finally {
        client.release();
    }
});
app.put('/api/admin/faculty/:userId', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, auth_key, dept_id } = req.body;
    await pool.query('UPDATE faculty_profiles SET faculty_name=$1, authorization_key=$2, dept_id=$3 WHERE user_id=$4', [name, auth_key, dept_id, req.params.userId]);
    res.json({ message: "Faculty Profile Updated" });
});

app.delete('/api/admin/faculty/:userId', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM users WHERE id = $1 AND role = \'faculty\'', [req.params.userId]);
    res.json({ message: "Faculty Deleted" });
});

// ==========================================
// 5. STUDENT CRUD & CR PROMOTION
// ==========================================
app.post('/api/admin/students', authenticateToken, authorize(['admin']), async (req, res) => {
    const { roll, name, email, section_id } = req.body;
    await pool.query('INSERT INTO students (roll_number, full_name, email, section_id) VALUES ($1,$2,$3,$4)', [roll, name, email, section_id]);
    res.json({ message: "Student Added" });
});

app.get('/api/admin/students', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT s.*, sec.section_name FROM students s JOIN sections sec ON s.section_id = sec.id');
    res.json(result.rows);
});

app.put('/api/admin/students/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, roll, email, section_id } = req.body;
    await pool.query('UPDATE students SET full_name=$1, roll_number=$2, email=$3, section_id=$4 WHERE id=$5', [name, roll, email, section_id, req.params.id]);
    res.json({ message: "Student Updated" });
});

app.delete('/api/admin/students/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM students WHERE id = $1', [req.params.id]);
    res.json({ message: "Student Deleted" });
});

app.post('/api/admin/promote-cr', authenticateToken, authorize(['admin']), async (req, res) => {
    const { student_id, password, semester } = req.body; // Added semester

    try {
        const student = await pool.query('SELECT email FROM students WHERE id = $1', [student_id]);
        if (student.rows.length === 0) return res.status(404).json({ error: "Student not found" });

        const hash = await bcrypt.hash(password, 10);
        
        await pool.query(
            'INSERT INTO users (email, password_hash, role, student_id, semester) VALUES ($1, $2, \'cr\', $3, $4)', 
            [student.rows[0].email, hash, student_id, semester || 1] // Default to 1 if not provided
        );
        
        res.json({ message: "Student promoted to Class Representative (CR)" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/demote-cr/:studentId', authenticateToken, authorize(['admin']), async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM users WHERE student_id = $1 AND role = \'cr\'', 
            [req.params.studentId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: "User not found or not a CR" });
        }

        res.json({ message: "CR privileges removed successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// ==========================================
// 6. COURSE CRUD
// ==========================================
app.post('/api/admin/courses', authenticateToken, authorize(['admin']), async (req, res) => {
    const { code, name, credits, dept_id } = req.body;
    await pool.query('INSERT INTO courses (course_code, course_name, credits, dept_id) VALUES ($1,$2,$3,$4)', [code, name, credits, dept_id]);
    res.json({ message: "Course Created" });
});

app.get('/api/admin/courses', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM courses');
    res.json(result.rows);
});


app.put('/api/admin/courses/:code', authenticateToken, authorize(['admin']), async (req, res) => {
    // Added dept_id to the destructuring and query
    const { name, credits, dept_id } = req.body;
    
    try {
        await pool.query(
            'UPDATE courses SET course_name=$1, credits=$2, dept_id=$3 WHERE course_code=$4', 
            [name, credits, dept_id, req.params.code]
        );
        res.json({ message: "Course Updated" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error" });
    }
});
app.delete('/api/admin/courses/:code', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM courses WHERE course_code = $1', [req.params.code]);
    res.json({ message: "Course Deleted" });
});

// ==========================================
// 7. TIMETABLE CRUD & VIEW
// ==========================================
app.post('/api/admin/timetable', authenticateToken, authorize(['admin']), async (req, res) => {
    const { section_id, semester, day, slot, course_code, faculty_id, room } = req.body;
    await pool.query('INSERT INTO timetable (section_id, semester, day, slot_number, course_code, faculty_profile_id, room_info) VALUES ($1,$2,$3,$4,$5,$6,$7)', [section_id, semester, day, slot, course_code, faculty_id, room]);
    res.json({ message: "Slot Added" });
});

app.get('/api/common/timetable', authenticateToken, async (req, res) => {
    const { section_id, semester } = req.query;
    const sql = `SELECT t.*, c.course_name, f.faculty_name FROM timetable t 
                 JOIN courses c ON t.course_code = c.course_code 
                 JOIN faculty_profiles f ON t.faculty_profile_id = f.id 
                 WHERE section_id = $1 AND semester = $2 ORDER BY day, slot_number`;
    const result = await pool.query(sql, [section_id, semester]);
    res.json(result.rows);
});

app.put('/api/admin/timetable/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { day, slot, course_code, faculty_id, room } = req.body;
    await pool.query('UPDATE timetable SET day=$1, slot_number=$2, course_code=$3, faculty_profile_id=$4, room_info=$5 WHERE id=$6', [day, slot, course_code, faculty_id, room, req.params.id]);
    res.json({ message: "Slot Updated" });
});

app.delete('/api/admin/timetable/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM timetable WHERE id = $1', [req.params.id]);
    res.json({ message: "Slot Deleted" });
});


app.put('/api/faculty/regen-token', authenticateToken, authorize(['faculty']), async (req, res) => {
    const newToken = generate6DigitToken();
    await pool.query('UPDATE faculty_profiles SET authorization_key = $1 WHERE user_id = $2', [newToken, req.user.id]);
    res.json({ message: "New Token Generated", token: newToken });
});


app.get('/api/cr/my-courses', authenticateToken, authorize(['cr']), async (req, res) => {
    const sql = `
        SELECT DISTINCT c.*
        FROM courses c
        JOIN timetable t ON c.course_code = t.course_code
        JOIN students s ON t.section_id = s.section_id
        WHERE s.id = $1
        ORDER BY c.course_name ASC`;
    try {
        // console.log(req.user.student_id);
        const result = await pool.query(sql, [req.user.student_id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



// app.post('/api/cr/attendance', authenticateToken, authorize(['cr', 'faculty', 'admin']), async (req, res) => {
//     const { timetable_id, date, records, selected_course_code, is_free } = req.body;
//     const client = await pool.connect();
    
//     try {
//         await client.query('BEGIN');

//         const ttResult = await client.query(
//             'SELECT course_code, faculty_profile_id, section_id FROM timetable WHERE id = $1', 
//             [timetable_id]
//         );
        
//         if (ttResult.rows.length === 0) throw new Error("Timetable slot not found");
        
//         const scheduledCourse = ttResult.rows[0].course_code;
//         const originalFacultyId = ttResult.rows[0].faculty_profile_id; 
//         const sectionId = ttResult.rows[0].section_id;

//         let category = 'normal';
//         if (is_free) category = 'free';
//         else if (selected_course_code !== scheduledCourse) category = 'swap';

//         // 3. Insert into attendance_sessions
//         const sessSql = `
//             INSERT INTO attendance_sessions 
//             (timetable_id, session_date, marked_by_user_id, session_category, actual_course_code) 
//             VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        
//         const sessRes = await client.query(sessSql, [
//             timetable_id, 
//             date, 
//             req.user.id, 
//             category, 
//             is_free ? null : selected_course_code
//         ]);
//         const sessionId = sessRes.rows[0].id;

//         if (category !== 'free' && records && records.length > 0) {
//             for (let r of records) {
//                 const status = r.status.toLowerCase(); 
//                 await client.query(
//                     'INSERT INTO attendance_records (session_id, student_id, status) VALUES ($1, $2, $3)', 
//                     [sessionId, r.id, status]
//                 );
//             }
//         }

//         // ============================================================
//         // 5. AUTO-LOG SWAP ENTRY (If Swap or Free)
//         // ============================================================
//         if (category === 'swap' || category === 'free') {
            
//             let targetFacultyId = null;

//             if (category === 'swap') {
//                 // LOGIC: Find the Faculty who teaches the "Selected Course" to this "Section"
//                 // We look for ANY slot in the timetable where this course is taught to this section
//                 const targetFacRes = await client.query(
//                     `SELECT faculty_profile_id FROM timetable 
//                      WHERE section_id = $1 AND course_code = $2 
//                      LIMIT 1`,
//                     [sectionId, selected_course_code]
//                 );

//                 if (targetFacRes.rows.length > 0) {
//                     targetFacultyId = targetFacRes.rows[0].faculty_profile_id;
//                 } else {
//                     // Fallback: If logged-in user is a faculty member, assume they are the substitute
//                     if (req.user.role === 'faculty') {
//                         const loggedInFac = await client.query(
//                             'SELECT id FROM faculty_profiles WHERE user_id = $1', 
//                             [req.user.id]
//                         );
//                         if (loggedInFac.rows.length > 0) targetFacultyId = loggedInFac.rows[0].id;
//                     }
//                 }
//             }

//             const swapReason = category === 'free' 
//                 ? 'Class declared Free during attendance marking' 
//                 : `Course changed from ${scheduledCourse} to ${selected_course_code}`;

//             await client.query(`
//                 INSERT INTO class_swaps 
//                 (source_timetable_id, requesting_faculty_id, target_faculty_id, requested_date, reason, status)
//                 VALUES ($1, $2, $3, $4, $5, 'approved')`,
//                 [timetable_id, originalFacultyId, targetFacultyId, date, swapReason]
//             );
//         }

//         await client.query('COMMIT');
//         res.json({ message: "Attendance processed and swap logged", sessionId, category });

//     } catch (e) { 
//         await client.query('ROLLBACK'); 
//         console.error(e);
//         res.status(500).json({ error: e.message }); 
//     } finally { 
//         client.release(); 
//     }
// });

app.post('/api/cr/attendance', authenticateToken, authorize(['cr', 'faculty', 'admin']), async (req, res) => {
    const { timetable_id, date, records, selected_course_code, is_free } = req.body;
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

    
        const existingCheck = await client.query(
            'SELECT id FROM attendance_sessions WHERE timetable_id = $1 AND session_date = $2',
            [timetable_id, date]
        );

        if (existingCheck.rows.length > 0) {
            
            throw new Error("Attendance has already been marked for this slot on this date.");
        }
        const ttResult = await client.query(
            'SELECT course_code, faculty_profile_id, section_id FROM timetable WHERE id = $1', 
            [timetable_id]
        );
        
        if (ttResult.rows.length === 0) throw new Error("Timetable slot not found");
        
        const scheduledCourse = ttResult.rows[0].course_code;
        const originalFacultyId = ttResult.rows[0].faculty_profile_id; 
        const sectionId = ttResult.rows[0].section_id;

    
        let category = 'normal';
        if (is_free) category = 'free';
        else if (selected_course_code !== scheduledCourse) category = 'swap';

        
        const sessSql = `
            INSERT INTO attendance_sessions 
            (timetable_id, session_date, marked_by_user_id, session_category, actual_course_code) 
            VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        
        const sessRes = await client.query(sessSql, [
            timetable_id, 
            date, 
            req.user.id, 
            category, 
            is_free ? null : selected_course_code
        ]);
        const sessionId = sessRes.rows[0].id;

        if (category !== 'free' && records && records.length > 0) {
            for (let r of records) {
                const status = r.status.toLowerCase(); 
                await client.query(
                    'INSERT INTO attendance_records (session_id, student_id, status) VALUES ($1, $2, $3)', 
                    [sessionId, r.id, status]
                );
            }
        }

        
        if (category === 'swap' || category === 'free') {
            let targetFacultyId = null;

            if (category === 'swap') {
                const targetFacRes = await client.query(
                    `SELECT faculty_profile_id FROM timetable 
                     WHERE section_id = $1 AND course_code = $2 
                     LIMIT 1`,
                    [sectionId, selected_course_code]
                );

                if (targetFacRes.rows.length > 0) {
                    targetFacultyId = targetFacRes.rows[0].faculty_profile_id;
                } else {
                    if (req.user.role === 'faculty') {
                        const loggedInFac = await client.query(
                            'SELECT id FROM faculty_profiles WHERE user_id = $1', 
                            [req.user.id]
                        );
                        if (loggedInFac.rows.length > 0) targetFacultyId = loggedInFac.rows[0].id;
                    }
                }
            }

            const swapReason = category === 'free' 
                ? 'Class declared Free during attendance marking' 
                : `Course changed from ${scheduledCourse} to ${selected_course_code}`;

            await client.query(`
                INSERT INTO class_swaps 
                (source_timetable_id, requesting_faculty_id, target_faculty_id, requested_date, reason, status)
                VALUES ($1, $2, $3, $4, $5, 'approved')`,
                [timetable_id, originalFacultyId, targetFacultyId, date, swapReason]
            );
        }

        await client.query('COMMIT');
        res.json({ message: "Attendance processed and swap logged", sessionId, category });

    } catch (e) { 
        await client.query('ROLLBACK'); 
        console.error("Attendance Error:", e.message);
        
      
        if (e.message.includes("already been marked")) {
            res.status(409).json({ error: e.message });
        } else {
            res.status(500).json({ error: e.message }); 
        }
    } finally { 
        client.release(); 
    }
});

app.get('/api/common/week-grid', authenticateToken, async (req, res) => {
    try {
        const { section_id, start_date, semester } = req.query; 

        const sql = `
            SELECT 
                t.*, 
                c.course_name,                  -- Scheduled Course Name
                f.faculty_name, 
                sess.id AS session_id,
                sess.session_category, 
                sess.session_date,
                sess.actual_course_code,        -- <--- ADDED: The Swapped Course Code
                ac.course_name AS actual_course_name -- <--- ADDED: The Swapped Course Name
            FROM timetable t
            JOIN courses c ON t.course_code = c.course_code
            JOIN faculty_profiles f ON t.faculty_profile_id = f.id 
            
            -- Join Attendance Session to check status
            LEFT JOIN attendance_sessions sess 
                ON sess.timetable_id = t.id 
                AND sess.session_date = (
                    $2::date + (CASE t.day 
                        WHEN 'Mon' THEN 0 
                        WHEN 'Tue' THEN 1
                        WHEN 'Wed' THEN 2 
                        WHEN 'Thu' THEN 3 
                        WHEN 'Fri' THEN 4
                        ELSE 0 
                    END)
                )
            
            -- Join Courses AGAIN to get the name of the 'Actual/Swapped' course
            LEFT JOIN courses ac ON sess.actual_course_code = ac.course_code

            WHERE t.section_id = $1 AND t.semester = $3
            ORDER BY t.day, t.slot_number`;

        const result = await pool.query(sql, [section_id, start_date, semester]);
        res.json(result.rows);

    } catch (err) {
        console.error("Week Grid Error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/common/timetable-by-class', authenticateToken, async (req, res) => {
    try {
        let section_id = req.query.section_id;
        let semester = req.query.semester;

        // Logic: If parameters are NOT provided, derive them from the Logged-in CR/Student
        if (!section_id || !semester) {
            
            if (!req.user.student_id) {
                return res.status(403).json({ error: "Not a student/CR account, and no parameters provided." });
            }

            // Fetch Section (from Student table) and Semester (from User table)
            const contextSql = `
                SELECT s.section_id, u.semester 
                FROM users u
                JOIN students s ON u.student_id = s.id
                WHERE u.id = $1
            `;
            
            const contextRes = await pool.query(contextSql, [req.user.id]);

            if (contextRes.rows.length === 0) {
                return res.status(404).json({ error: "User details not found" });
            }

            section_id = contextRes.rows[0].section_id;
            semester = contextRes.rows[0].semester;
        }

        // --- Main Timetable Query ---
        const sql = `
            SELECT 
                t.*,
                c.course_name,
                f.faculty_name
            FROM timetable t
            JOIN courses c ON t.course_code = c.course_code
            -- Updated to join on Profile ID based on your new schema
            JOIN faculty_profiles f ON t.faculty_profile_id = f.id
            WHERE t.section_id = $1 AND t.semester = $2
            ORDER BY t.day, t.slot_number
        `;

        const result = await pool.query(sql, [section_id, semester]);
        res.json(result.rows);

    } catch (err) {
        console.error("Timetable by class error:", err);
        res.status(500).json({ error: err.message });
    }
});
// Get all attendance sessions for a specific timetable slot (Admin View)
app.get('/api/admin/sessions-by-timetable/:ttId', authenticateToken, authorize(['admin']), async (req, res) => {
    try {
        const sql = `
            SELECT sess.id, sess.session_date, sess.is_verified_by_faculty, u.email as marked_by
            FROM attendance_sessions sess
            JOIN users u ON sess.marked_by_user_id = u.id
            WHERE sess.timetable_id = $1
            ORDER BY sess.session_date DESC`;
        const result = await pool.query(sql, [req.params.ttId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get detailed student records for a specific session ID
app.get('/api/admin/records-by-session/:sessionId', authenticateToken, authorize(['admin']), async (req, res) => {
    try {
        const sql = `
            SELECT s.roll_number, s.full_name, r.status
            FROM attendance_records r
            JOIN students s ON r.student_id = s.id
            WHERE r.session_id = $1
            ORDER BY s.roll_number ASC`;
        const result = await pool.query(sql, [req.params.sessionId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// Get students for a specific timetable slot
app.get('/api/cr/students-by-timetable/:ttId', authenticateToken, authorize(['cr', 'admin']), async (req, res) => {
    try {
        const sql = `
            SELECT s.* 
            FROM students s 
            JOIN timetable t ON s.section_id = t.section_id 
            WHERE t.id = $1
            ORDER BY s.roll_number ASC`;
        const result = await pool.query(sql, [req.params.ttId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/cr/students-by-studentid', authenticateToken, authorize(['cr', 'admin']), async (req, res) => {
    try {
        const sql = `
            SELECT s.* 
            FROM students s 
            WHERE s.section_id=(select section_id from students where id=$1)
            ORDER BY s.roll_number ASC`;
        const result = await pool.query(sql, [req.user.student_id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});




app.put('/api/faculty/verify', authenticateToken, authorize(['cr', 'faculty']), async (req, res) => {
    const { token, timetable_id } = req.body; 

    try {
        const timetableResult = await pool.query(
            'SELECT faculty_profile_id FROM timetable WHERE id = $1',
            [timetable_id]
        );

        if (timetableResult.rows.length === 0) {
            return res.status(404).json({ error: "Timetable slot not found" });
        }

        const facultyProfileId = timetableResult.rows[0].faculty_profile_id;
        const profile = await pool.query(
            'SELECT authorization_key FROM faculty_profiles WHERE id = $1',
            [facultyProfileId]
        );

        if (profile.rows.length === 0) {
            return res.status(404).json({ error: "Faculty profile not found" });
        }

        if (profile.rows[0].authorization_key !== token) {
            return res.status(401).json({ error: "Invalid 6-digit Token" });
        }
        // await pool.query(
        //     'UPDATE attendance_sessions SET is_verified_by_faculty = true, verified_at = NOW() WHERE id = $1',
        //     [req.params.sessionId]
        // );

        res.json({ message: "Attendance verified and locked" });

    } catch (err) {
        console.error('Verification error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/students-by-filter', authenticateToken, async (req, res) => {
    try {
        const { section_id, semester } = req.query; 

        if (!section_id) {
            return res.status(400).json({ error: "Section ID is required" });
        }

        let sql = `
            SELECT DISTINCT
                s.id, 
                s.roll_number, 
                s.full_name, 
                s.email, 
                sec.section_name, 
                b.batch_name, 
                u.role,
                u.semester as cr_semester
            FROM students s
            JOIN sections sec ON s.section_id = sec.id
            JOIN batches b ON sec.batch_id = b.id
            LEFT JOIN users u ON s.id = u.student_id
        `;

        let params = [section_id];

        if (semester) {
            // If semester is provided, join with timetable
            sql += `
                JOIN timetable t 
                  ON s.section_id = t.section_id 
                 AND t.semester = $2
                WHERE s.section_id = $1
            `;
            params.push(semester);
        } else {
            // If semester is NOT provided, just filter by section
            sql += `
                WHERE s.section_id = $1
            `;
        }

        sql += ` ORDER BY s.roll_number ASC`;

        const result = await pool.query(sql, params);
        res.json(result.rows);

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});



// GET Daily Attendance Overview (Specific Date & Section)
app.get('/api/admin/daily-attendance-overview', authenticateToken, async (req, res) => {
    try {
        const { section_id, date, semester } = req.query; // date format: YYYY-MM-DD

        if (!section_id || !date || !semester) {
            return res.status(400).json({ error: "Missing parameters" });
        }

        // 1. Determine the Day of Week (e.g., 'Mon', 'Tue') to filter the timetable
        const dayName = new Date(date).toLocaleDateString('en-US', { weekday: 'short' });

        const sql = `
            SELECT 
                t.slot_number,
                c.course_name AS scheduled_course_name,
                f.faculty_name,
                
                -- Session Data
                sess.id AS session_id,
                sess.session_category,
                sess.is_verified_by_faculty,
                sess.actual_course_code,
                ac.course_name AS actual_course_name, -- Name of swapped course
                
                -- Aggregated Counts (Subqueries for efficiency)
                (SELECT COUNT(*)::int FROM attendance_records r WHERE r.session_id = sess.id AND LOWER(r.status) = 'present') AS present_count,
                (SELECT COUNT(*)::int FROM attendance_records r WHERE r.session_id = sess.id AND LOWER(r.status) = 'absent') AS absent_count,
                (SELECT COUNT(*)::int FROM attendance_records r WHERE r.session_id = sess.id) AS total_count

            FROM timetable t
            JOIN courses c ON t.course_code = c.course_code
            JOIN faculty_profiles f ON t.faculty_profile_id = f.id
            
            -- Left Join to find if attendance marked for THIS specific date
            LEFT JOIN attendance_sessions sess 
                ON t.id = sess.timetable_id 
                AND sess.session_date = $2::date -- $2 IS NOW THE DATE
            
            -- Join for swapped course name
            LEFT JOIN courses ac ON sess.actual_course_code = ac.course_code

            WHERE t.section_id = $1     -- $1 IS SECTION ID
              AND t.semester = $3       -- $3 IS SEMESTER (Integer)
              AND t.day = $4            -- $4 IS DAY NAME (String)
            ORDER BY t.slot_number ASC`;

        // CORRECTED PARAMETER ORDER:
        // $1: section_id
        // $2: date
        // $3: semester
        // $4: dayName
        const result = await pool.query(sql, [section_id, date, semester, dayName]);
        
        res.json(result.rows);

    } catch (err) {
        console.error("Daily Overview Error:", err);
        res.status(500).json({ error: err.message });
    }
});


// ==========================================
// 8. FACULTY SPECIFIC TIMETABLE VIEWS (GROUPED FORMAT)
// ==========================================

const groupTimetableData = (rows) => {
    const grouped = rows.reduce((acc, row) => {
        const { full_class_title, ...slotDetails } = row;
        
        if (!acc[full_class_title]) {
            acc[full_class_title] = [];
        }
        

        acc[full_class_title].push(slotDetails);
        return acc;
    }, {});
    
    
    return [grouped];
};

app.get('/api/faculty/my-schedule', authenticateToken, authorize(['faculty', 'admin']), async (req, res) => {
    try {
        let targetProfileId;

        if (req.query.faculty_id) {
           
            if (req.user.role !== 'admin') {
                return res.status(403).json({ error: "Access Denied" });
            }
            targetProfileId = req.query.faculty_id;
        } else {
            
            const profileRes = await pool.query('SELECT id FROM faculty_profiles WHERE user_id = $1', [req.user.id]);
            if (profileRes.rows.length === 0) {
                return res.status(404).json({ error: "Faculty profile not found for this user." });
            }
            targetProfileId = profileRes.rows[0].id;
        }

        const sql = `
            SELECT 
                t.id as timetable_id,
                t.day, 
                t.slot_number, 
                t.room_info, 
                t.semester,
                c.course_name, 
                c.course_code,
                
                -- Title for Grouping (Removed Semester from title to allow easier filtering)
                CONCAT(d.dept_code, ' ', b.batch_name, ' (', s.section_name, ')') as full_class_title
            
            FROM timetable t
            JOIN courses c ON t.course_code = c.course_code
            JOIN sections s ON t.section_id = s.id
            JOIN batches b ON s.batch_id = b.id
            JOIN departments d ON b.dept_id = d.id
            WHERE t.faculty_profile_id = $1
            ORDER BY 
                t.semester,
                CASE t.day 
                    WHEN 'Mon' THEN 1 WHEN 'Tue' THEN 2 WHEN 'Wed' THEN 3 
                    WHEN 'Thu' THEN 4 WHEN 'Fri' THEN 5 WHEN 'Sat' THEN 6 ELSE 7 
                END, 
                t.slot_number`;
        
        const result = await pool.query(sql, [targetProfileId]);
        res.json(groupTimetableData(result.rows));

    } catch (err) {
        console.error("My Schedule Error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/faculty/my-classes-full-timetables', authenticateToken, authorize(['faculty']), async (req, res) => {
    try {
        const sql = `
            WITH MySections AS (
                -- Find sections this faculty teaches
                SELECT DISTINCT t.section_id, t.semester
                FROM timetable t
                JOIN faculty_profiles f ON t.faculty_profile_id = f.id
                WHERE f.user_id = $1
            )
            SELECT 
                t.id as timetable_id,
                t.day, 
                t.slot_number,
                t.room_info,
                t.semester,
                c.course_name, 
                c.course_code,
                f.faculty_name, -- Shows who teaches this specific slot
                
                -- Title for Grouping
                CONCAT(d.dept_code, ' Batch ', b.start_year, '-', b.end_year, ' Section ', s.section_name, ' Sem ', t.semester) as full_class_title
            
            FROM timetable t
            JOIN MySections ms ON t.section_id = ms.section_id AND t.semester = ms.semester
            JOIN courses c ON t.course_code = c.course_code
            JOIN faculty_profiles f ON t.faculty_profile_id = f.id
            JOIN sections s ON t.section_id = s.id
            JOIN batches b ON s.batch_id = b.id
            JOIN departments d ON b.dept_id = d.id
            
            ORDER BY 
                full_class_title,
                CASE t.day 
                    WHEN 'Mon' THEN 1 WHEN 'Tue' THEN 2 WHEN 'Wed' THEN 3 
                    WHEN 'Thu' THEN 4 WHEN 'Fri' THEN 5 WHEN 'Sat' THEN 6 ELSE 7 
                END, 
                t.slot_number`;

        const result = await pool.query(sql, [req.user.id]);
        res.json(groupTimetableData(result.rows));

    } catch (err) {
        console.error("My Classes Full Timetables Error:", err);
        res.status(500).json({ error: err.message });
    }
});


// BULK FACULTY PROFILE UPLOAD

app.post('/api/admin/faculty-bulk-upload', authenticateToken, authorize(['admin']), async (req, res) => {
    const { profiles } = req.body; // Array of {name, email, dept_id, auth_key}
    
    if (!Array.isArray(profiles) || profiles.length === 0) {
        return res.status(400).json({ error: "No profiles provided" });
    }

    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        // Prepare bulk insert values
        const values = [];
        const params = [];
        let paramIndex = 1;

        profiles.forEach(p => {
            values.push(`($${paramIndex}, $${paramIndex + 1}, $${paramIndex + 2}, $${paramIndex + 3})`);
            params.push(p.name, p.email, p.dept_id, p.auth_key);
            paramIndex += 4;
        });

        const insertSql = `
            INSERT INTO faculty_profiles (faculty_name, email, dept_id, authorization_key)
            VALUES ${values.join(', ')}
        `;

        await client.query(insertSql, params);
        
        await client.query('COMMIT');

        res.json({ 
            success: true,
            message: `${profiles.length} faculty profiles created successfully` 
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Bulk Upload Error:', err);
        
        res.status(500).json({ 
            error: err.message,
            detail: err.detail || undefined
        });
    } finally {
        client.release();
    }
});


// OPTIMIZED BULK STUDENT UPLOAD

app.post('/api/admin/student-bulk-upload', authenticateToken, authorize(['admin']), async (req, res) => {
    const { students } = req.body; // Array of {roll, name, email, section_id}
    
    if (!Array.isArray(students) || students.length === 0) {
        return res.status(400).json({ error: "No students provided" });
    }

    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        const values = [];
        const params = [];
        let paramIndex = 1;

        students.forEach(s => {
            values.push(`($${paramIndex}, $${paramIndex + 1}, $${paramIndex + 2}, $${paramIndex + 3})`);
            params.push(s.roll, s.name, s.email, s.section_id);
            paramIndex += 4;
        });

        const insertSql = `
            INSERT INTO students (roll_number, full_name, email, section_id)
            VALUES ${values.join(', ')}
        `;

        await client.query(insertSql, params);
        
        await client.query('COMMIT');

        res.json({ 
            success: true,
            message: `${students.length} students created successfully` 
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Student Bulk Upload Error:', err);

        res.status(500).json({ 
            error: err.message,
            detail: err.detail || undefined
        });
    } finally {
        client.release();
    }
});


// Get Faculty's authorization key
app.get('/api/faculty/auth-key', authenticateToken, authorize(['faculty']), async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT authorization_key FROM faculty_profiles WHERE user_id = $1',
            [req.user.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Faculty profile not found" });
        }
        
        res.json({ authorization_key: result.rows[0].authorization_key });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update Faculty's authorization key
app.put('/api/faculty/auth-key', authenticateToken, authorize(['faculty']), async (req, res) => {
    const { authorization_key } = req.body;
    
    try {
        await pool.query(
            'UPDATE faculty_profiles SET authorization_key = $1 WHERE user_id = $2',
            [authorization_key, req.user.id]
        );
        
        res.json({ message: "Authorization key updated successfully", authorization_key });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



app.get('/api/student-report', async (req, res) => {
    const { roll_number, semester, start_date, end_date } = req.query;

    if (!roll_number) {
        return res.status(400).json({ error: "Roll number is required" });
    }
    if (!semester) {
        return res.status(400).json({ error: "Semester is required" });
    }

    const sql = `
        WITH StudentInfo AS (
            SELECT id, section_id 
            FROM students 
            WHERE roll_number = $1
        )
        SELECT 
            c.course_name, 
            c.course_code, 
            -- 1. Count Total Sessions held for the Section in this Semester
            COUNT(sess.id) AS total_classes,
            -- 2. Count Attended Sessions (Check if record exists AND is present)
            COUNT(CASE WHEN LOWER(r.status) = 'present' THEN 1 END) AS attended_classes,
            -- 3. Calculate Percentage
            COALESCE(ROUND(
                (COUNT(CASE WHEN LOWER(r.status) = 'present' THEN 1 END)::numeric / 
                NULLIF(COUNT(sess.id), 0)) * 100, 2
            ), 0) AS attendance_percentage
        FROM attendance_sessions sess
        -- Link Session to Timetable to verify Section and Semester
        JOIN timetable t ON sess.timetable_id = t.id
        -- Link to Courses to get Course Name
        JOIN courses c ON sess.actual_course_code = c.course_code
        -- LEFT JOIN: Get records for THIS student only (returns NULL if no record)
        LEFT JOIN attendance_records r 
            ON sess.id = r.session_id 
            AND r.student_id = (SELECT id FROM StudentInfo)
        WHERE 
            -- Filter sessions by the Student's Section
            t.section_id = (SELECT section_id FROM StudentInfo)
            -- Filter by Semester
            AND t.semester = $2
            -- Filter out free periods
            AND sess.session_category != 'free'
            -- Optional Date Filters
            AND ($3::date IS NULL OR sess.session_date >= $3)
            AND ($4::date IS NULL OR sess.session_date <= $4)
        GROUP BY c.course_name, c.course_code
        ORDER BY c.course_name ASC;
    `;

    try {
        const result = await pool.query(sql, [
            roll_number, 
            semester, 
            start_date || null, 
            end_date || null
        ]);
        
        // Return empty array if no sessions found, but don't error out
        res.json(result.rows);
    } catch (err) {
        console.error("Database Error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get('/api/admin/attendance-report', async (req, res) => {
    // REMOVED threshold from destructuring
    const { section_id, course_code, semester, start_date, end_date } = req.query;

    if (!section_id) return res.status(400).json({ error: "Section ID is required" });
    if (!semester) return res.status(400).json({ error: "Semester is required" });

    const sql = `
        WITH 
        -- 1. Get Configured Courses from TIMETABLE for this Section & Semester
        --    Ensures the Subject column exists even if Total Classes = 0
        distinct_courses AS (
            SELECT DISTINCT 
                t.course_code as actual_course_code, 
                c.course_name
            FROM timetable t
            JOIN courses c ON t.course_code = c.course_code
            WHERE t.section_id = $1
            AND t.semester = $3  -- Parameter $3 is Semester
        ),

        -- 2. Count Total Sessions per Course
        SessionCounts AS (
            SELECT 
                dc.actual_course_code,
                dc.course_name,
                COUNT(sess.id) as total_sessions
            FROM distinct_courses dc
            LEFT JOIN attendance_sessions sess 
                ON dc.actual_course_code = sess.actual_course_code
                AND sess.timetable_id IN (SELECT id FROM timetable WHERE section_id = $1)
                AND sess.session_category != 'free'
                AND ($4::date IS NULL OR sess.session_date >= $4) -- Parameter $4 is Start Date
                AND ($5::date IS NULL OR sess.session_date <= $5) -- Parameter $5 is End Date
            WHERE ($2::text = 'ALL' OR dc.actual_course_code = $2)
            GROUP BY dc.actual_course_code, dc.course_name
        ),

        -- 3. Get All Students in the Section
        SectionStudents AS (
            SELECT id, roll_number, full_name 
            FROM students 
            WHERE section_id = $1
        ),

        -- 4. Get Actual Attendance Counts (Only Present)
        RawAttendance AS (
            SELECT 
                r.student_id,
                sess.actual_course_code,
                COUNT(*) as attended_count
            FROM attendance_records r
            JOIN attendance_sessions sess ON r.session_id = sess.id
            JOIN timetable t ON sess.timetable_id = t.id
            WHERE t.section_id = $1
            AND t.semester = $3
            AND LOWER(r.status) = 'present'
            AND ($4::date IS NULL OR sess.session_date >= $4)
            AND ($5::date IS NULL OR sess.session_date <= $5)
            GROUP BY r.student_id, sess.actual_course_code
        )

        -- 5. Final Report: Cross Join Students x Courses -> Left Join Attendance
        SELECT 
            s.roll_number,
            s.full_name,
            COALESCE(sc.course_name, sc.actual_course_code) as subject,
            COALESCE(sc.total_sessions, 0) as total,
            COALESCE(ra.attended_count, 0) as attended,
            ROUND(
                (COALESCE(ra.attended_count, 0)::decimal / NULLIF(sc.total_sessions, 0)) * 100, 
            1) as percentage
        FROM SectionStudents s
        CROSS JOIN SessionCounts sc
        LEFT JOIN RawAttendance ra 
            ON s.id = ra.student_id 
            AND sc.actual_course_code = ra.actual_course_code
        ORDER BY s.roll_number, sc.actual_course_code;
    `;

    try {
        const result = await pool.query(sql, [
            section_id, 
            course_code || 'ALL', 
            semester,         // $3
            start_date || null, // $4
            end_date || null    // $5
        ]);
        res.json(result.rows);
    } catch (err) {
        console.error("Attendance Report Error:", err);
        res.status(500).json({ error: err.message });
    }
});

// app.get('/api/attendance/periodic',authenticateToken, authorize(['faculty','admin']), async (req, res) => {
//     const sectionId = req.query.sectionId;
//     const semester = req.query.semester;
//     const courseCode = req.query.courseCode;
//     const month = req.query.month; // YYYY-MM
  
//     if (!sectionId || !semester || !courseCode || !month) {
//       return res.status(400).json({ error: "Missing required parameters" });
//     }
  
//     // Validate month format
//     if (!/^\d{4}-\d{2}$/.test(month)) {
//       return res.status(400).json({ error: "month must be in YYYY-MM format" });
//     }
  
//     try {
//       // Query for monthly attendance
//       const monthlyResult = await pool.query(
//         `
//         SELECT
//           s.id AS student_id,
//           s.roll_number AS student_name,
//           sess.session_date::date AS date,
//           t.slot_number AS slot,
//           LOWER(r.status) AS status
//         FROM students s
//         JOIN attendance_records r ON r.student_id = s.id
//         JOIN attendance_sessions sess ON r.session_id = sess.id
//         JOIN timetable t ON sess.timetable_id = t.id
//         WHERE s.section_id = $1
//           AND t.semester = $2
//           AND sess.actual_course_code = $3
//           AND DATE_TRUNC('month', sess.session_date) = DATE_TRUNC('month', $4::date)
//           AND sess.session_category != 'free'
//         ORDER BY s.roll_number, sess.session_date, t.slot_number
//         `,
//         [sectionId, semester, courseCode, `${month}-01`]
//       );

//       // Query for TOTAL attendance (all months for this course)
//       // ✅ Both 'present' AND 'late' count as attended
//       const totalResult = await pool.query(
//         `
//         SELECT
//           s.id AS student_id,
//           COUNT(*) AS total_classes,
//           SUM(CASE WHEN LOWER(r.status) IN ('present', 'late') THEN 1 ELSE 0 END) AS total_attended
//         FROM students s
//         JOIN attendance_records r ON r.student_id = s.id
//         JOIN attendance_sessions sess ON r.session_id = sess.id
//         JOIN timetable t ON sess.timetable_id = t.id
//         WHERE s.section_id = $1
//           AND t.semester = $2
//           AND sess.actual_course_code = $3
//           AND sess.session_category != 'free'
//         GROUP BY s.id
//         `,
//         [sectionId, semester, courseCode]
//       );

//       // Create a map for total attendance data
//       const totalsMap = {};
//       for (const row of totalResult.rows) {
//         totalsMap[row.student_id] = {
//           totalClasses: parseInt(row.total_classes),
//           totalAttended: parseInt(row.total_attended),
//           overallPercentage: row.total_classes > 0 
//             ? parseFloat(((row.total_attended / row.total_classes) * 100).toFixed(2))
//             : 0
//         };
//       }
  
//       // Group monthly data
//       const map = {};
  
//       for (const row of monthlyResult.rows) {
//         if (!map[row.student_id]) {
//           map[row.student_id] = {
//             studentId: row.student_id,
//             studentName: row.student_name,
//             records: [],
//             attended: 0,
//             total: 0,
//             monthlyPercentage: 0,
//             // Add total attendance data
//             totalClasses: totalsMap[row.student_id]?.totalClasses || 0,
//             totalAttended: totalsMap[row.student_id]?.totalAttended || 0,
//             overallPercentage: totalsMap[row.student_id]?.overallPercentage || 0
//           };
//         }
  
//         map[row.student_id].records.push({
//           date: row.date,
//           slot: row.slot,
//           status: row.status
//         });
  
//         map[row.student_id].total += 1;
//         // ✅ Both 'present' AND 'late' count as attended for monthly too
//         if (row.status === 'present' || row.status === 'late') {
//           map[row.student_id].attended += 1;
//         }
//       }

//       // Calculate monthly percentage and add students with no attendance in this month
//       for (const studentId in map) {
//         const student = map[studentId];
//         student.monthlyPercentage = student.total > 0 
//           ? parseFloat(((student.attended / student.total) * 100).toFixed(2))
//           : 0;
//       }

//       // Add students who have total attendance but no attendance this month
//       const allStudents = await pool.query(
//         'SELECT id, roll_number FROM students WHERE section_id = $1 ORDER BY roll_number',
//         [sectionId]
//       );

//       for (const student of allStudents.rows) {
//         if (!map[student.id] && totalsMap[student.id]) {
//           map[student.id] = {
//             studentId: student.id,
//             studentName: student.roll_number,
//             records: [],
//             attended: 0,
//             total: 0,
//             monthlyPercentage: 0,
//             totalClasses: totalsMap[student.id].totalClasses,
//             totalAttended: totalsMap[student.id].totalAttended,
//             overallPercentage: totalsMap[student.id].overallPercentage
//           };
//         }
//       }
  
//       res.json(Object.values(map));
  
//     } catch (err) {
//       console.error(err);
//       res.status(500).json({ error: "Failed to fetch periodic attendance" });
//     }
//   });

// app.get('/api/attendance/periodic', authenticateToken, authorize(['faculty', 'admin']), async (req, res) => {
//     const { sectionId, semester, courseCode, month } = req.query;
  
//     if (!sectionId || !semester || !courseCode || !month) {
//       return res.status(400).json({ error: "Missing required parameters" });
//     }
  
//     try {
//       // 1. Get ALL Students in the Section (Base List)
//       const studentsRes = await pool.query(
//         `SELECT id, roll_number, full_name 
//          FROM students 
//          WHERE section_id = $1 
//          ORDER BY roll_number`,
//         [sectionId]
//       );
//       const allStudents = studentsRes.rows;

//       // 2. Get ALL Sessions for the Month (The Columns)
//       const sessionsRes = await pool.query(
//         `SELECT 
//             sess.id AS session_id,
//             sess.session_date::date AS date,
//             t.slot_number AS slot
//          FROM attendance_sessions sess
//          JOIN timetable t ON sess.timetable_id = t.id
//          WHERE t.section_id = $1
//            AND t.semester = $2
//            AND sess.actual_course_code = $3
//            AND TO_CHAR(sess.session_date, 'YYYY-MM') = $4
//            AND sess.session_category != 'free'
//          ORDER BY sess.session_date, t.slot_number`,
//         [sectionId, semester, courseCode, month]
//       );
//       const allSessions = sessionsRes.rows;

//       // 3. Get ALL Attendance Records for these sessions
//       // We leverage the session IDs we just found
//       const sessionIds = allSessions.map(s => s.session_id);
//       let allRecords = [];
      
//       if (sessionIds.length > 0) {
//         const recordsRes = await pool.query(
//             `SELECT session_id, student_id, LOWER(status) as status
//              FROM attendance_records 
//              WHERE session_id = ANY($1::int[])`,
//             [sessionIds]
//         );
//         allRecords = recordsRes.rows;
//       }

//       // 4. Get Overall Totals (For the Semester)
//       const totalsRes = await pool.query(
//         `SELECT 
//             r.student_id,
//             COUNT(sess.id) as total_classes,
//             COUNT(CASE WHEN LOWER(r.status) IN ('present', 'late') THEN 1 END) as attended
//          FROM attendance_records r
//          JOIN attendance_sessions sess ON r.session_id = sess.id
//          JOIN timetable t ON sess.timetable_id = t.id
//          WHERE t.section_id = $1
//            AND t.semester = $2
//            AND sess.actual_course_code = $3
//            AND sess.session_category != 'free'
//          GROUP BY r.student_id`,
//         [sectionId, semester, courseCode]
//       );
      
//       // Convert totals to a Map for O(1) lookup
//       const totalsMap = {};
//       totalsRes.rows.forEach(r => {
//         totalsMap[r.student_id] = {
//             total: parseInt(r.total_classes),
//             attended: parseInt(r.attended)
//         };
//       });

//       // ==========================================================
//       // 5. CONSTRUCT THE GRID (Cross-Reference Students x Sessions)
//       // ==========================================================
      
//       const responseData = allStudents.map(student => {
//         const studentId = student.id;
//         const studentName = student.roll_number; // Or full_name if you prefer

//         // Build records for EVERY session found
//         const records = allSessions.map(session => {
//             // Find record for this specific student & session
//             const record = allRecords.find(r => 
//                 r.session_id === session.session_id && 
//                 r.student_id === studentId
//             );

//             return {
//                 date: session.date,
//                 slot: session.slot,
//                 // If record exists, use status. If not, implies ABSENT (or Unmarked)
//                 status: record ? record.status : 'absent' 
//             };
//         });

//         // Calculate Monthly Stats
//         const monthlyTotal = records.length;
//         const monthlyAttended = records.filter(r => 
//             r.status === 'present' || r.status === 'late'
//         ).length;
        
//         const monthlyPercentage = monthlyTotal > 0 
//             ? ((monthlyAttended / monthlyTotal) * 100).toFixed(0) 
//             : 0;

//         // Get Overall Stats
//         const overallData = totalsMap[studentId] || { total: 0, attended: 0 };
//         const overallPercentage = overallData.total > 0
//             ? ((overallData.attended / overallData.total) * 100).toFixed(1)
//             : 0;

//         return {
//             studentId,
//             studentName,
//             records,
//             monthlySummary: {
//                 attended: monthlyAttended,
//                 total: monthlyTotal,
//                 percentage: monthlyPercentage
//             },
//             totalClasses: overallData.total,
//             totalAttended: overallData.attended,
//             overallPercentage: parseFloat(overallPercentage)
//         };
//       });
  
//       res.json(responseData);
  
//     } catch (err) {
//       console.error(err);
//       res.status(500).json({ error: "Failed to fetch periodic attendance" });
//     }
// });

app.get('/api/attendance/periodic', authenticateToken, authorize(['faculty', 'admin']), async (req, res) => {
    const { sectionId, semester, courseCode, month } = req.query;
  
    if (!sectionId || !semester || !courseCode || !month) {
      return res.status(400).json({ error: "Missing required parameters" });
    }
  
    try {
      // 1. Get ALL Students in the Section
      const studentsRes = await pool.query(
        `SELECT id, roll_number, full_name 
         FROM students 
         WHERE section_id = $1 
         ORDER BY roll_number`,
        [sectionId]
      );
      const allStudents = studentsRes.rows;

      // 2. Get ALL Sessions for the Month
      const sessionsRes = await pool.query(
        `SELECT 
            sess.id AS session_id,
            sess.session_date::date AS date,
            t.slot_number AS slot
         FROM attendance_sessions sess
         JOIN timetable t ON sess.timetable_id = t.id
         WHERE t.section_id = $1
           AND t.semester = $2
           AND sess.actual_course_code = $3
           AND TO_CHAR(sess.session_date, 'YYYY-MM') = $4
           AND sess.session_category != 'free'
         ORDER BY sess.session_date, t.slot_number`,
        [sectionId, semester, courseCode, month]
      );
      const allSessions = sessionsRes.rows;

      // 3. Get ALL Attendance Records for these sessions
      const sessionIds = allSessions.map(s => s.session_id);
      let allRecords = [];
      
      if (sessionIds.length > 0) {
        const recordsRes = await pool.query(
            `SELECT session_id, student_id, LOWER(status) as status
             FROM attendance_records 
             WHERE session_id = ANY($1::int[])`,
            [sessionIds]
        );
        allRecords = recordsRes.rows;
      }

      // 4. Get Overall Totals (Approximate based on existing records)
      const totalsRes = await pool.query(
        `SELECT 
            r.student_id,
            COUNT(sess.id) as total_classes,
            COUNT(CASE WHEN LOWER(r.status) IN ('present', 'late') THEN 1 END) as attended
         FROM attendance_records r
         JOIN attendance_sessions sess ON r.session_id = sess.id
         JOIN timetable t ON sess.timetable_id = t.id
         WHERE t.section_id = $1
           AND t.semester = $2
           AND sess.actual_course_code = $3
           AND sess.session_category != 'free'
         GROUP BY r.student_id`,
        [sectionId, semester, courseCode]
      );
      
      const totalsMap = {};
      totalsRes.rows.forEach(r => {
        totalsMap[r.student_id] = {
            total: parseInt(r.total_classes),
            attended: parseInt(r.attended)
        };
      });

      // 5. Construct Response
      const responseData = allStudents.map(student => {
        const studentId = student.id;
        const studentName = student.roll_number;

        // Map every session to a status
        const records = allSessions.map(session => {
            const record = allRecords.find(r => 
                r.session_id === session.session_id && 
                r.student_id === studentId
            );

            // KEY CHANGE: Return 'unmarked' if no record found
            return {
                date: session.date,
                slot: session.slot,
                status: record ? record.status : 'unmarked' 
            };
        });

        const monthlyTotal = records.length;
        const monthlyAttended = records.filter(r => 
            r.status === 'present' || r.status === 'late'
        ).length;
        
        const monthlyPercentage = monthlyTotal > 0 
            ? ((monthlyAttended / monthlyTotal) * 100).toFixed(0) 
            : 0;

        const overallData = totalsMap[studentId] || { total: 0, attended: 0 };
        const overallPercentage = overallData.total > 0
            ? ((overallData.attended / overallData.total) * 100).toFixed(1)
            : 0;

        return {
            studentId,
            studentName,
            records,
            monthlySummary: {
                attended: monthlyAttended,
                total: monthlyTotal,
                percentage: monthlyPercentage
            },
            totalClasses: overallData.total,
            totalAttended: overallData.attended,
            overallPercentage: parseFloat(overallPercentage)
        };
      });
  
      res.json(responseData);
  
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to fetch periodic attendance" });
    }
});
app.listen(3000, () => console.log("Server Running on 3000"));
