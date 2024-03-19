const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const collection = require('./config');
const path = require('path');
const session = require('express-session');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.set('views', path.join(__dirname, '..', 'views'));
app.set('view engine', 'ejs');

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true
}));

const absolutePath = path.join(__dirname, '..', 'views', 'home.html');
const homeHtmlPath = path.join(__dirname, '..', 'views', 'home.html');

app.get('/', (req, res) => {
    res.sendFile(absolutePath);
});

app.get('/isLoggedIn', (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    res.json({ isLoggedIn });
});

app.get('/login', (req, res) => {
    // Check if the user is already logged in
    const isLoggedIn = false; // Placeholder, replace with your actual logic

    if (isLoggedIn) {
        // Perform logout logic
        // ...

        // Redirect to the home page after logout
        return res.redirect('/home.html');
    } else {
        // Render the login page
        res.render('login');
    }
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.get('/home.html', (req, res) => {
    res.sendFile(homeHtmlPath);
});

app.get('/aboutPage.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'aboutPage.html'));
});

app.get('/ganimlist.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'ganimlist.html'));
});

app.get('/selfPage.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'selfPage.html'));
});

app.get('/HomeLog.html', (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;

    if (isLoggedIn) {
        res.sendFile(path.join(__dirname, '..', 'views', 'HomeLog.html'));
    } else {
        res.redirect('/home.html');
    }
});


app.post('/signup', async (req, res) => {
    const data = {
        fullname: req.body.fullname,
        email: req.body.useremail,
        password: req.body.password,
        role: req.body.role,
    };

    try {
        const existingUser = await collection.findOne({ email: data.email });

        if (existingUser) {
            return res.send('<script>alert("User already exists. Please choose a different email."); window.location.href = "/signup";</script>');
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(data.password, saltRounds);

        data.password = hashedPassword;

        const userdata = await collection.create(data);
        console.log(userdata);
        return res.send('<script>alert("ההרשמה בוצעה בהצלחה"); window.location.href = "/";</script>');
    } catch (error) {
        console.error('Error during signup:', error);
        return res.status(500).send('Internal Server Error');
    }
});

app.post('/login', async (req, res) => {
    try {
        const check = await collection.findOne({ email: req.body.useremail });

        if (!check) {
            return res.send('<script>alert("משתמש לא קיים"); window.location.href = "/";</script>');
        }

        const isPasswordMatch = await bcrypt.compare(req.body.password, check.password);

        if (isPasswordMatch) {
            req.session.isLoggedIn = true;
            return res.redirect('/HomeLog.html');
        } else {
            return res.send('<script>alert("סיסמא לא נכונה"); window.location.href = "/";</script>');
        }
    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).send('Internal Server Error');
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});