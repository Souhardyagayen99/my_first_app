// controllers/users_controller.js

const User = require('../models/user');
const bcrypt = require('bcrypt');

// Render the user profile page
module.exports.profile = async function(req, res) {
    try {
        // Fetch user by cookie (user_id)
        if (!req.cookies.user_id) {
            return res.redirect('/users/sign-in');
        }

        const user = await User.findById(req.cookies.user_id);

        if (user) {
            return res.render('user_profile', {
                title: 'User Profile',
                user: user
            });
        } else {
            return res.redirect('/users/sign-in');
        }
    } catch (err) {
        console.log('Error in fetching user:', err);
        return res.redirect('back');
    }
};

// Render the sign-up page
module.exports.signUp = function(req, res) {
    return res.render('user_sign_up', {
        title: 'Codeial | Sign Up'
    });
};

// Render the sign-in page
module.exports.signIn = function(req, res) {
    return res.render('user_sign_in', {
        title: 'Codeial | Sign In'
    });
};

// Handle user registration
module.exports.create = async function(req, res) {
    try {
        // Check password confirmation
        if (req.body.password != req.body.confirm_password) {
            console.log('Passwords do not match');
            return res.redirect('back');
        }

        // Check if user already exists
        let user = await User.findOne({ email: req.body.email });

        if (!user) {
            // Hash the password
            const hashedPassword = await bcrypt.hash(req.body.password, 10);

            // Create new user
            await User.create({
                email: req.body.email,
                password: hashedPassword,
                name: req.body.name
            });

            console.log('User created successfully');
            return res.redirect('/users/sign-in');
        } else {
            console.log('User already exists');
            return res.redirect('back');
        }
    } catch (err) {
        console.log('Error in creating user:', err);
        return res.redirect('back');
    }
};

// Handle sign-in (session creation)
module.exports.createSession = async function(req, res) {
    try {
        let user = await User.findOne({ email: req.body.email });

        if (user) {
            const match = await bcrypt.compare(req.body.password, user.password);

            if (match) {
                // Set cookie (for now - replace with express-session later)
                res.cookie('user_id', user.id);
                console.log('User logged in successfully');
                return res.redirect('/users/profile');
            } else {
                console.log('Invalid credentials');
                return res.redirect('back');
            }
        } else {
            console.log('User not found');
            return res.redirect('back');
        }
    } catch (err) {
        console.log('Error in creating session:', err);
        return res.redirect('back');
    }
};

// Handle logout (clear cookie)
module.exports.destroySession = function(req, res) {
    res.clearCookie('user_id');
    console.log('User logged out');
    return res.redirect('/');
};
