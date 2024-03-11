const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const collection = require('./config');
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(express.static(path.join(__dirname, '..', 'public')));

// Set the views directory
app.set('views', path.join(__dirname, '..', 'views'));
app.set('view engine', 'ejs');

const absolutePath = path.join(__dirname, '..', 'views', 'home.html');

app.get('/', (req, res) => {
    res.sendFile(absolutePath);
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/signup', (req, res) => {
    res.render('signup');
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
            return res.redirect('/home');
        } else {
            return res.send('<script>alert("סיסמא לא נכונה"); window.location.href = "/";</script>');
        }
    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).send('Internal Server Error');
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


