const mongoose = require("mongoose");

const connect = mongoose.connect("mongodb+srv://Ganli:Ganli123@ganli.7my2zmp.mongodb.net/", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    dbName: "ganli", // replace "your_database_name" with your actual database name
    user: "Ganli", // replace "Ganli" with your actual username
    pass: "Ganli123", // replace "your_password" with your actual password
});


connect
    .then(() => {
        console.log("Database connected successfully");
    })
    .catch((error) => {
        console.error("Database connection failed:", error.message);
    });

const LoginSchema = new mongoose.Schema({
    fullname: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['parent', 'teacher', 'admin'],
        required: true
    }
});

const collection = mongoose.model("users", LoginSchema);

module.exports = collection;
