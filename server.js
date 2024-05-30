const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Schema } = mongoose;

const app = express();
app.use(bodyParser.json());

// Environment variables (replace with your actual values)
const MONGODB_URI = 'mongodb+srv://divimeesala:divya@cluster0.i0ggl74.mongodb.net/devhub'; 
const JWT_SECRET = 'your_jwt_secret';

// MongoDB Connection
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('MongoDB connected');
});

// User Schema
const userSchema = new Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    posts: [{ type: Schema.Types.ObjectId, ref: 'Post' }]
});
const User = mongoose.model('User', userSchema);

// Post Schema
const postSchema = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    likes: { type: Number, default: 0 },
    comments: [{
        body: String,
        date: { type: Date, default: Date.now },
        user: { type: Schema.Types.ObjectId, ref: 'User' }
    }]
});
const Post = mongoose.model('Post', postSchema);

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization').replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Register Endpoint
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        let existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error in register:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Login Endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const payload = { user: { id: user.id, email: user.email, username: user.username } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.status(200).json({ token });
        });
    } catch (error) {
        console.error('Error in login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();
        res.status(200).json({ resetToken });
    } catch (error) {
        console.error('Error in forgot password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
    const { resetToken, newPassword } = req.body;
    try {
        const user = await User.findOne({
            resetPasswordToken: resetToken,
            resetPasswordExpires: { $gt: Date.now() },
        });
        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Error in reset password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Create a new post
app.post('/posts', authenticateToken, async (req, res) => {
    const { content } = req.body;
    try {
        const newPost = new Post({ user: req.user.id, content });
        await newPost.save();
        await User.findByIdAndUpdate(req.user.id, { $push: { posts: newPost._id } });
        res.status(201).json(newPost);
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Read all posts
app.get('/posts', async (req, res) => {
    try {
        const posts = await Post.find().populate('user', 'username');
        res.json(posts);
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Read a single post by ID
app.get('/posts/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const post = await Post.findById(id).populate('user', 'username');
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }
        res.json(post);
    } catch (error) {
        console.error('Error fetching post:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update a post by ID
app.put('/posts/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    try {
        const post = await Post.findById(id);
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }
        if (post.user.toString() !== req.user.id) {
            return res.status(401).json({ message: 'User not authorized' });
        }
        post.content = content;
        await post.save();
        res.json(post);
    } catch (error) {
        console.error('Error updating post:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete a post by ID
app.delete('/posts/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const post = await Post.findOne({ _id: id });
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }
        if (post.user.toString() !== req.user.id) {
            return res.status(401).json({ message: 'User not authorized' });
        }

        // Remove post from Post collection
        await Post.deleteOne({ _id: id });

        // Remove post ID from User's posts array
        await User.findByIdAndUpdate(req.user.id, { $pull: { posts: id } });

        res.json({ message: 'Post removed' });
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// Delete all posts of the authenticated user
app.delete('/posts', authenticateToken, async (req, res) => {
    try {
        const posts = await Post.find({ user: req.user.id });
        if (!posts || posts.length === 0) {
            return res.status(404).json({ message: 'No posts found for this user' });
        }
        await Post.deleteMany({ user: req.user.id });
        await User.findByIdAndUpdate(req.user.id, { $set: { posts: [] } });
        res.json({ message: 'All posts removed' });
    } catch (error) {
        console.error('Error deleting all posts:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Like a post by ID
app.post('/posts/:id/like', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const post = await Post.findById(id);
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }
        post.likes += 1;
        await post.save();
        res.json(post);
    } catch (error) {
        console.error('Error liking post:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Add a comment to a post by ID
app.post('/posts/:id/comment', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { comment } = req.body; // Assuming req.body.comment contains the comment text

    try {
        const post = await Post.findById(id);
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }

        const newComment = {
            body: comment,
            user: req.user.id,
            date: new Date()
        };

        post.comments.push(newComment);
        await post.save();

        res.json(post); // Return the updated post object with comments
    } catch (error) {
        console.error('Error adding comment to post:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// Start server
const PORT = process.env.PORT || 5010;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});

