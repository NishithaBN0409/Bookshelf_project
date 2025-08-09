const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs'); // For password hashing
const jwt = require('jsonwebtoken'); // For JWT tokens

const app = express();

// Middleware
app.use(cors()); // Allows cross-origin requests (important for frontend-backend communication)
app.use(bodyParser.json()); // Parses incoming request bodies as JSON

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/bookshelf')
    .then(() => console.log('MongoDB connected successfully'))
    .catch(err => console.error('MongoDB connection error:', err));

// JWT Secret (!!! IMPORTANT: Change this to a strong, random string in production !!!)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// --- Mongoose Schemas ---

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Book Schema (add userId to link books to users)
const bookSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    author: { type: String, required: true, trim: true },
    genre: { type: String, required: true, trim: true },
    publishedYear: Number,
    pages: Number,
    isbn: String,
    read: { type: Boolean, default: false },
    favorite: { type: Boolean, default: false },
    description: String,
    coverUrl: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true } // Link to User
});

const Book = mongoose.model('Book', bookSchema);

// --- Authentication Middleware ---
// This middleware verifies the JWT token from the request header
function auth(req, res, next) {
    // Get token from header
    const authHeader = req.header('Authorization');

    // Check if Authorization header exists and starts with 'Bearer '
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    // Extract token (remove "Bearer " prefix)
    const token = authHeader.split(' ')[1];

    try {
        // Verify token
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user; // Attach user info (id, username) to the request object
        next(); // Proceed to the next middleware/route handler
    } catch (err) {
        // If token is invalid or expired
        res.status(401).json({ message: 'Token is not valid' });
    }
}

// --- Authentication Routes ---

// Register a new user
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check if user with given email already exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User with that email already exists' });
        }
        // Check if username is already taken
        user = await User.findOne({ username });
        if (user) {
            return res.status(400).json({ message: 'Username already taken' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10); // Generate a salt
        const hashedPassword = await bcrypt.hash(password, salt); // Hash the password with the salt

        // Create new user
        user = new User({ username, email, password: hashedPassword });
        await user.save(); // Save user to database

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Compare provided password with hashed password in DB
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Create JWT payload
        const payload = {
            user: {
                id: user.id, // MongoDB's _id is converted to 'id' by Mongoose
                username: user.username
            }
        };

        // Sign the token
        jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: '1h' }, // Token expires in 1 hour
            (err, token) => {
                if (err) throw err;
                // Send token, user ID, and username back to client
                res.json({ token, userId: user.id, username: user.username });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// --- Book Routes (Protected by 'auth' middleware) ---

// Get all books for the authenticated user
app.get('/api/books', auth, async (req, res) => {
    try {
        // Find books where the userId matches the authenticated user's ID
        const books = await Book.find({ userId: req.user.id });
        res.json(books);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Server error fetching books' });
    }
});

// Add a new book for the authenticated user
app.post('/api/books', auth, async (req, res) => {
    const book = new Book({
        ...req.body, // Spread all fields from the request body
        userId: req.user.id // Assign the book to the authenticated user
    });

    try {
        const newBook = await book.save(); // Save the new book
        res.status(201).json(newBook); // Respond with the created book
    } catch (err) {
        console.error(err.message);
        res.status(400).json({ message: 'Error adding book', error: err.message });
    }
});

// Update an existing book for the authenticated user
app.put('/api/books/:id', auth, async (req, res) => {
    try {
        // Find and update the book by its ID, ensuring it belongs to the authenticated user
        const book = await Book.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id }, // Query: match ID and userId
            req.body, // Update with request body
            { new: true, runValidators: true } // Return the updated document, run schema validators
        );
        if (!book) {
            // If book not found or doesn't belong to user
            return res.status(404).json({ message: 'Book not found or not authorized to update' });
        }
        res.json(book); // Respond with the updated book
    } catch (err) {
        console.error(err.message);
        res.status(400).json({ message: 'Error updating book', error: err.message });
    }
});

// Delete a book for the authenticated user
app.delete('/api/books/:id', auth, async (req, res) => {
    try {
        // Find and delete the book by its ID, ensuring it belongs to the authenticated user
        const book = await Book.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
        if (!book) {
            // If book not found or doesn't belong to user
            return res.status(404).json({ message: 'Book not found or not authorized to delete' });
        }
        res.json({ message: 'Book deleted successfully' }); // Respond with success message
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Server error deleting book' });
    }
});

// --- Serve Static Frontend Files (Optional, for production deployment) ---
// If you want to serve your frontend from the same Node.js server:
// app.use(express.static('public')); // Assuming your index.html is in a 'public' folder
// app.get('*', (req, res) => { // For single-page applications, serve index.html for all other routes
//     res.sendFile(path.resolve(__dirname, 'public', 'index.html'));
// });


// Start server
const PORT = process.env.PORT || 3001; // Server will run on port 3001
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});


const path = require('path');

// Serve static files from the folder where index.html is located
app.use(express.static(path.join(__dirname)));

// Serve index.html for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
