const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { collection, Gan } = require('./config');
const fs = require('fs').promises;
const path = require('path');
const session = require('express-session');
const nodemailer = require('nodemailer');

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

app.get('/gantamp.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'gantamp.html'));
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
        console.log('Request body:', req.body);
        const check = await collection.findOne({ email: req.body.useremail });

        if (!check) {
            return res.send('<script>alert("משתמש לא קיים"); window.location.href = "/";</script>');
        }

        const isPasswordMatch = await bcrypt.compare(req.body.password, check.password);

        if (isPasswordMatch) {
            req.session.isLoggedIn = true;
            req.session.userEmail = check.email;
            req.session.userRole = check.role;
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
        const { notification } = req.body;
        const ganData = {
            ganName: req.body.ganName,
            gordenName: req.body.gordenName,
            buildYear: req.body.buildYear,
            NumOfkids: req.body.NumOfkids,
            price: req.body.price,
            address: req.body.address,
            character: req.body.character,
            maxKids: req.body.maxKids,
            workTime: req.body.workTime,
            vision: req.body.vision,
            principles: req.body.principles,
            notifications: notification ? [{ text: notification }] : []
        };

        let gan;
        if (req.body.ganId) {
            // Update existing gan
            gan = await Gan.findByIdAndUpdate(req.body.ganId, ganData, { new: true });
        } else {
            // Create new gan
            ganData.createdBy = req.session.userEmail;
            gan = await Gan.create(ganData);
        }

        // Create or update the HTML file for the gan
        const ganHtmlContent = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <link rel="stylesheet" href="/navibar.css" />
                <link rel="stylesheet" href="/ganTamp.css" />
                <title>${ganData.ganName}</title>
            </head>
            <body>
                <header>
                    <bar>
                        <ul>
                        <li><a href="/selfPage" id="selfPageLink">אזור אישי</a></li>
                            <li><a href="/ganimlist.html">גנים</a></li>
                            <li><a href="/aboutPage.html">אודות</a></li>
                            <li><a href="/HomeLog.html">בית</a></li>
                            <li><a href="/HomeLog.html" class="logo">גן-לי</a></li>
                            <li>
                                <a href="/logout" class="login" id="logoutLink">התנתקות</a>
                            </li>
                        </ul>
                    </bar>
                </header>
                <main class="inner">
                    <section class="frame-group">
                        <div class="frame-container">
                            <div class="frame-div">
                                <div class="frame-parent1">
                                    <div class="rectangle-group">
                                        <div class="frame-item"></div>
                                        <div class="container">
                                            <div class="div5">:התראות מן הגן</div>
                                        </div>
                                        <div class="div6">
                                            <p class="p">${ganData.notifications.map(n => n.text).join('<br>')}</p>
                                        </div>
                                    </div>
                                    <div class="frame-parent2">
                                        <div class="rectangle-container">
                                            <div class="frame-inner"></div>
                                            <div class="div7">:חזון הגן</div>
                                            <div class="div8">
                                                <p class="p2">${ganData.vision}</p>
                                            </div>
                                        </div>
                                        <div class="rectangle-parent1">
                                            <div class="rectangle-div"></div>
                                            <div class="div9">:עקרונות הגן</div>
                                            <div class="div10">
                                                <ol class="ol">
                                                    <li class="li">${ganData.principles}</li>
                                                </ol>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="frame-parent3">
                                <div class="rectangle-parent2">
                                    <div class="frame-child1"></div>
                                    <div class="div10">
                                        <span>שם הגן:</span>
                                        <span class="span">${ganData.ganName}</span>
                                    </div>
                                    <div class="div11">
                                        <span>שם הגננת:</span>
                                        <span class="span">${ganData.gordenName}</span>
                                    </div>
                                    <div class="div13">
                                        <span>שנת הקמה:</span>
                                        <span class="span2">${ganData.buildYear}</span>
                                    </div>
                                    <div class="div14">
                                        <span>אופי הגן:</span>
                                        <span class="span3">${ganData.character}</span>
                                    </div>
                                    <div class="div16">
                                        <span>מספר ילדים:</span>
                                        <span class="span5">${ganData.NumOfkids}</span>
                                    </div>
                                    <div class="div17">
                                        <span>מחיר:</span>
                                        <span class="span6">${ganData.price}</span>
                                    </div>
                                    <div class="div19">
                                        <p class="p4">
                                            <span class="span8">שעות פעילות:</span>
                                            <span> </span>
                                        </p>
                                        <p class="p5">${ganData.workTime}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="rectangle-parent3">
                            <div class="rectangle-parent4">
                                <div class="frame-child3"></div>
                                <div class="frame-parent4">
                                    <!-- Reviews section -->
                                </div>
                                <div class="frame">
                                    <div class="div23">הוסף ביקורת</div>
                                </div>
                            </div>
                        </div>
                    </section>
                </main>
                <!--REPLACE_WITH_ADMIN_BUTTONS-->
            </body>
            <script>
                // Get the user's role from the server
                fetch('/profile')
                    .then(response => response.json())
                    .then(data => {
                        const userRole = data.role;
                        const selfPageLink = document.getElementById('selfPageLink');

                        // Update the selfPageLink based on the user's role
                        if (userRole === 'הורה') {
                            selfPageLink.href = '/selfPageP.html';
                        } else if (userRole === 'גננת') {
                            selfPageLink.href = '/selfPageG.html';
                        } else if (userRole === 'admin') {
                            selfPageLink.href = '/selfPageA.html';
                        }

                        // Check if the user is an admin
                        if (userRole === 'admin') {
                            // Inject the edit and delete buttons for admin users
                            const adminButtonsContainer = document.createElement('div');
                            adminButtonsContainer.innerHTML = \`
                            
                            \`;
                            document.body.appendChild(adminButtonsContainer);
                        }
                    })
                    .catch(error => {
                        console.error('Error fetching user role:', error);
                    });

                // Function to edit a gan
                function editGan(ganId) {
                    window.location.href = \`/editGan.html?ganId=\${ganId}\`;
                }

                // Function to delete a gan
                function deleteGan(ganId) {
                    if (confirm('האם אתה בטוח שברצונך למחוק את הגן?')) {
                        fetch(\`/gans/\${ganId}\`, { method: 'DELETE' })
                            .then(response => {
                                if (response.ok) {
                                    alert('הגן נמחק בהצלחה');
                                    window.location.href = '/ganimlist.html';
                                } else {
                                    alert('שגיאה במחיקת הגן');
                                }
                            })
                            .catch(error => {
                                console.error('Error deleting gan:', error);
                                alert('שגיאה במחיקת הגן');
                            });
                    }
                }
            </script>
            </html>
        `;

        // Save the HTML file for the gan
        const ganHtmlPath = path.join(__dirname, '..', 'views', `${gan.ganName}.html`);
        await fs.writeFile(ganHtmlPath, ganHtmlContent);

        res.send('<script>alert("Gan saved successfully"); window.location.href = "/selfPageG.html";</script>');
    } catch (error) {
        console.error('Error saving gan:', error);
        res.status(500).send('Internal Server Error');
    }
});
// Route to get the list of gans waiting for approval
app.get('/gans/waiting', async (req, res) => {
    try {
        const gans = await Gan.find({ approved: false });
        res.json(gans);
    } catch (error) {
        console.error('Error fetching gans waiting for approval:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route to approve a gan
app.put('/gans/:ganId/approve', async (req, res) => {
    try {
        const { ganId } = req.params;
        await Gan.findByIdAndUpdate(ganId, { approved: true });
        res.sendStatus(200);
    } catch (error) {
        console.error('Error approving gan:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route to delete a gan
app.delete('/gans/:ganId', async (req, res) => {
    try {
        const { ganId } = req.params;
        // Delete the gan from the database
        await Gan.findByIdAndDelete(ganId);

        // Delete the HTML file associated with the gan
        const ganHtmlPath = path.join(__dirname, '..', 'views', `${ganId}.html`);
        await fs.unlink(ganHtmlPath);

        res.sendStatus(200);
    } catch (error) {
        console.error('Error deleting gan:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route to get the list of approved gans
app.get('/gans/approved', async (req, res) => {
    try {
        const gans = await Gan.find({ approved: true });
        res.json(gans);
    } catch (error) {
        console.error('Error fetching approved gans:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/gan/:ganId', async (req, res) => {
    try {
        const { ganId } = req.params;
        const gan = await Gan.findById(ganId);

        if (!gan) {
            return res.status(404).send('Gan not found');
        }

        const isAdmin = req.session.userRole === 'admin';
        const isGorden = req.session.userEmail === gan.gordenName;

        const ganHtmlPath = path.join(__dirname, '..', 'views', `${gan.ganName}.html`);
        let ganHtmlContent = await fs.readFile(ganHtmlPath, 'utf-8');

        // Inject the isAdmin and isGorden values into the HTML content
        ganHtmlContent = ganHtmlContent.replace(
            '<!--REPLACE_WITH_ADMIN_GORDEN_STATUS-->',
            `<script>
                var isAdmin = ${isAdmin};
                var isGorden = ${isGorden};
            </script>`
        );

        // Inject the edit and delete buttons for admin users
        if (isAdmin) {
            ganHtmlContent = ganHtmlContent.replace(
                '<!--REPLACE_WITH_ADMIN_BUTTONS-->',
                `<div class="admin-buttons">
                    <button onclick="editGan('${gan._id}')">עריכת עמוד</button>
                    <button onclick="deleteGan('${gan._id}')">מחיקת גן</button>
                </div>`
            );
        }

        res.send(ganHtmlContent);
    } catch (error) {
        console.error('Error fetching gan:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/ganTamp.css', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'ganTamp.css'));
});

app.get('/gans/byUser', async (req, res) => {
    try {
        if (!req.session.isLoggedIn) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const userRole = req.session.userRole;
        if (userRole !== 'גננת') {
            return res.status(403).json({ error: 'Forbidden' });
        }

        const userEmail = req.query.email;
        const gans = await Gan.find({ createdBy: userEmail });
        res.json(gans);
    } catch (error) {
        console.error('Error fetching gans by user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/gans/:ganId/approve', async (req, res) => {
    try {
        const { ganId } = req.params;
        const updatedGan = await Gan.findByIdAndUpdate(ganId, { approved: true }, { new: true });

        if (!updatedGan) {
            return res.status(404).json({ error: 'Gan not found' });
        }

        res.json(updatedGan);
    } catch (error) {
        console.error('Error approving gan:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/gans/byUser', async (req, res) => {
    try {
        if (!req.session.isLoggedIn) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const userRole = req.session.userRole;
        if (userRole !== 'גננת') {
            return res.status(403).json({ error: 'Forbidden' });
        }

        const userEmail = req.query.email;
        const gans = await Gan.find({ createdBy: userEmail });
        res.json(gans);
    } catch (error) {
        console.error('Error fetching gans by user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/gans/:ganId/edit', async (req, res) => {
    try {
        const { ganId } = req.params;
        const gan = await Gan.findById(ganId);

        if (!gan) {
            return res.status(404).send('Gan not found');
        }

        res.json(gan);
    } catch (error) {
        console.error('Error fetching gan for editing:', error);
        res.status(500).send('Internal Server Error');
    }
});
app.get('/gans/:ganId/edit', async (req, res) => {
    try {
        const { ganId } = req.params;
        const gan = await Gan.findById(ganId);

        if (!gan) {
            return res.status(404).send('Gan not found');
        }

        res.json(gan);
    } catch (error) {
        console.error('Error fetching gan for editing:', error);
        res.status(500).send('Internal Server Error');
    }
});
app.get('/editGan.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'editGan.html'));
});
app.put('/gans/:ganId/notifications', async (req, res) => {
    try {
        const { ganId } = req.params;
        const { notification } = req.body;

        const updatedGan = await Gan.findByIdAndUpdate(
            ganId,
            { $push: { notifications: { text: notification } } },
            { new: true }
        );

        if (!updatedGan) {
            return res.status(404).json({ error: 'Gan not found' });
        }

        res.json(updatedGan);
    } catch (error) {
        console.error('Error updating gan notifications:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'forgot-password.html'));
});

app.post('/reset-password', async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        // Find the user by email
        const user = await collection.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Hash the new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update the user's password
        await collection.updateOne({ email }, { $set: { password: hashedPassword } });

        res.json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/gans/:ganName/review', async (req, res) => {
    try {
        const { ganName } = req.params;
        const { review } = req.body;
        const author = req.session.userEmail;

        console.log('Received review:', review);
        console.log('Author:', author);
        console.log('Gan name:', ganName);

        if (!author) {
            console.log('Unauthorized: No user email in session');
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const gan = await Gan.findOne({ ganName });

        if (!gan) {
            console.log('Gan not found:', ganName);
            return res.status(404).json({ error: 'Gan not found' });
        }

        console.log('Gan found:', gan);

        gan.reviews.push({ text: review, author });
        await gan.save();

        console.log('Review added successfully');
        res.json(gan);
    } catch (error) {
        console.error('Error adding review:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.get('/gans/:ganName', async (req, res) => {
    try {
        const { ganName } = req.params;
        const gan = await Gan.findOne({ ganName });

        if (!gan) {
            console.log('Gan not found:', ganName);
            return res.status(404).json({ error: 'Gan not found' });
        }

        console.log('Gan found:', gan);
        res.json(gan);
    } catch (error) {
        console.error('Error fetching gan:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/gans/:ganName/reviews/:reviewId', async (req, res) => {
    try {
        const { ganName, reviewId } = req.params;
        const userId = req.session.userEmail;
        const userRole = req.session.userRole;

        console.log('ganName:', ganName);
        console.log('reviewId:', reviewId);
        console.log('userId:', userId);
        console.log('userRole:', userRole);

        if (!ganName || !reviewId) {
            console.error('Missing required parameters:', { ganName, reviewId });
            return res.status(400).json({ error: 'Missing required parameters' });
        }

        const gan = await Gan.findOne({ ganName });

        console.log('Found gan:', gan);

        if (!gan) {
            console.error('Gan not found:', ganName);
            return res.status(404).json({ error: 'Gan not found' });
        }

        const review = gan.reviews.id(reviewId);

        console.log('Found review:', review);

        if (!review) {
            console.error('Review not found:', reviewId);
            return res.status(404).json({ error: 'Review not found' });
        }

        console.log('gan.createdBy:', gan.createdBy);

        if (userRole !== 'admin' && userId !== gan.createdBy) {
            console.error('Forbidden access attempt:', { userRole, userId, createdBy: gan.createdBy });
            return res.status(403).json({ error: 'Forbidden' });
        }

        review.remove();
        await gan.save();

        console.log('Review deleted successfully');

        res.json({ message: 'Review deleted successfully' });
    } catch (error) {
        console.error('Error deleting review:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});