require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const cors = require('cors');
const app = express();
const stripe = require('stripe')("sk_test_51QnE3jC7HhZ698AEia9uYBiqFkm1I5oqsJmxs5M8GSYmsQWwpISPlm7hRRBBajIpd8htnopyHUfcLbzUACCBMvBY00HYFHxRdy"); // Load Stripe secret key from .env


const PORT = process.env.PORT || 4000;
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

// Constants
const httpStatusText = {
    SUCCESS: 'success',
    FAIL: 'fail',
    ERROR: 'error'
};

const userRoles = {
    ADMIN: "ADMIN",
    USER: "USER",
    MANGER: "MANGER"
};

// Mongo Models
const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, required: true, unique: true },
    password: String,
    token: String,
    role: { type: String, enum: [userRoles.USER, userRoles.ADMIN, userRoles.MANGER], default: userRoles.USER }
});

const courseSchema = new mongoose.Schema({
    title: String,
    price: Number
});

const User = mongoose.model('User', userSchema);
const Course = mongoose.model('Course', courseSchema);

// Middleware
app.use(cors());
app.use(express.json());

// JWT Auth Middleware
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ status: httpStatusText.ERROR, message: 'token is required' });

    const token = authHeader.split(' ')[1];
    try {
        const currentUser = jwt.verify(token, JWT_SECRET_KEY);
        req.currentUser = currentUser;
        next();
    } catch {
        return res.status(401).json({ status: httpStatusText.ERROR, message: 'invalid token' });
    }
};

// Role check middleware
const allowedTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.currentUser.role)) {
            return res.status(401).json({ status: httpStatusText.ERROR, message: 'this role is not authorized' });
        }
        next();
    };
};

// Routes
// --- USERS ---
app.post('/api/users/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password, role } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ status: httpStatusText.FAIL, message: 'user already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ firstName, lastName, email, password: hashedPassword, role });
        const token = jwt.sign({ email, id: user._id, role: user.role }, JWT_SECRET_KEY, { expiresIn: '1h' });
        user.token = token;

        await user.save();
        res.status(201).json({ status: httpStatusText.SUCCESS, data: { user } });
    } catch (err) {
        res.status(500).json({ status: httpStatusText.ERROR, message: err.message });
    }
});

app.post('/api/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ status: httpStatusText.FAIL, message: 'email and password are required' });

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ status: httpStatusText.FAIL, message: 'user not found' });

        const matched = await bcrypt.compare(password, user.password);
        if (!matched) return res.status(401).json({ status: httpStatusText.FAIL, message: 'wrong password' });

        const token = jwt.sign({ email, id: user._id, role: user.role }, JWT_SECRET_KEY, { expiresIn: '1h' });
        userRole = user.role;
        res.json({ status: httpStatusText.SUCCESS, data: { token }, user: { userRole }, allData: { user } });
    } catch (err) {
        res.status(500).json({ status: httpStatusText.ERROR, message: err.message });
    }
});

app.get('/api/users', verifyToken, async (req, res) => {
    try {
        const users = await User.find({}, { password: 0, __v: 0 });
        res.json({ status: httpStatusText.SUCCESS, data: { users } });
    } catch (err) {
        res.status(500).json({ status: httpStatusText.ERROR, message: err.message });
    }
});

// --- COURSES ---
app.get('/api/courses', async (req, res) => {
    try {
        const courses = await Course.find({}, { __v: 0 });
        res.json({ status: httpStatusText.SUCCESS, data: { courses } });
    } catch (err) {
        res.status(500).json({ status: httpStatusText.ERROR, message: err.message });
    }
});

app.post('/api/courses', verifyToken, allowedTo(userRoles.MANGER, userRoles.ADMIN), [
    body('title').notEmpty().withMessage("title is required").isLength({ min: 2 }).withMessage("title must be at least 2 chars"),
    body('price').notEmpty().withMessage("price is required")
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ status: httpStatusText.FAIL, message: errors.array() });

    try {
        const newCourse = new Course(req.body);
        await newCourse.save();
        res.status(201).json({ status: httpStatusText.SUCCESS, data: { course: newCourse } });
    } catch (err) {
        res.status(500).json({ status: httpStatusText.ERROR, message: err.message });
    }
});

app.get('/api/courses/:courseId', async (req, res) => {
    try {
        const course = await Course.findById(req.params.courseId);
        if (!course) return res.status(404).json({ status: httpStatusText.FAIL, message: 'course not found' });

        res.json({ status: httpStatusText.SUCCESS, data: { course } });
    } catch (err) {
        res.status(500).json({ status: httpStatusText.ERROR, message: err.message });
    }
});

app.patch('/api/courses/:courseId', async (req, res) => {
    try {
        const updated = await Course.updateOne({ _id: req.params.courseId }, { $set: req.body });
        res.json({ status: httpStatusText.SUCCESS, data: { course: updated } });
    } catch (err) {
        res.status(500).json({ status: httpStatusText.ERROR, message: err.message });
    }
});

app.delete('/api/courses/:courseId', verifyToken, allowedTo(userRoles.ADMIN, userRoles.MANGER), async (req, res) => {
    try {
        await Course.deleteOne({ _id: req.params.courseId })
        res.json({ status: httpStatusText.SUCCESS, data: null });
    } catch (err) {
        res.status(500).json({ status: httpStatusText.ERROR, message: err.message });
    }
});

// --- Stripe Payment Integration ---
app.post("/api/create-payment-intent", async (req, res) => {
    try {
        const { amount } = req.body; // Amount should be sent from the frontend
        if (!amount) return res.status(400).json({ status: httpStatusText.FAIL, message: 'amount is required' });

        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount * 100, // Convert to cents
            currency: 'usd',
        });

        res.send({ clientSecret: paymentIntent.client_secret });
    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});



// Not found route
app.all('*', (req, res) => {
    res.status(404).json({ status: httpStatusText.ERROR, message: 'this resource is not available' });
});

// DB & Server start
mongoose.connect(MONGO_URL)
    .then(() => {
        console.log("MongoDB connected");
        app.listen(PORT, () => console.log("Server running on port", PORT));
    })
    .catch(err => console.error("Mongo error", err));
