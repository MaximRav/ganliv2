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

app.get('/home', (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;

    if (isLoggedIn) {
        res.redirect('/HomeLog.html');
    } else {
        res.redirect('/home.html');
    }
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

app.get('/selfPageP.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'selfPageP.html'));
});

app.get('/selfPageG.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'selfPageG.html'));
});

app.get('/selfPageA.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'selfPageA.html'));
});

app.get('/buildGan.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'buildGan.html'));
});

app.get('/buildGan.css', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'buildGan.css'));
});

app.get('/HomeLog.html', (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;

    if (isLoggedIn) {
        res.sendFile(path.join(__dirname, '..', 'views', 'HomeLog.html'));
    } else {
        res.redirect('/home.html');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
        }
        res.redirect('/home.html');
    });
});

app.post('/signup', async (req, res) => {
    const data = {
        fullname: req.body.fullname,
        email: req.body.useremail,
        password: req.body.password,
        role: req.body.role,
        phone: req.body.phone,
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
            req.session.userEmail = check.email;
            return res.redirect('/HomeLog.html');
        } else {
            return res.send('<script>alert("סיסמא לא נכונה"); window.location.href = "/";</script>');
        }
    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).send('Internal Server Error');
    }
});

app.get('/profile', async (req, res) => {
    try {
        if (!req.session.isLoggedIn) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const user = await collection.findOne({ email: req.session.userEmail });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const profileData = {
            fullname: user.fullname,
            email: user.email,
            phone: user.phone || '',
            role: user.role,
            profilePicture: user.profilePicture || 'https://via.placeholder.com/150'
        };

        res.json(profileData);
    } catch (error) {
        console.error('Error fetching profile data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/profile', async (req, res) => {
    try {
        if (!req.session.isLoggedIn) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const updatedProfileData = req.body;

        const result = await collection.updateOne(
            { email: req.session.userEmail },
            { $set: updatedProfileData }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/buildGan', async (req, res) => {
    try {
        const ganData = {
            ganName: req.body.ganName,
            buildYear: req.body.buildYear,
            NumOfGardens: req.body.NumOfGardens,
            price: req.body.price,
            address: req.body.address,
            character: req.body.character,
            maxKids: req.body.maxKids,
            workTime: req.body.workTime,
            description: req.body.description
        };



        res.send('<script>alert("Gan added successfully"); window.location.href = "/buildGan.html";</script>');
    } catch (error) {
        console.error('Error adding gan:', error);
        res.status(500).send('Internal Server Error');
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});