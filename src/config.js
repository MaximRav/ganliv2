const mongoose = require("mongoose");

const connect = mongoose.connect("mongodb+srv://Ganli:Ganli123@ganli.7my2zmp.mongodb.net/", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    dbName: "ganli",
    user: "Ganli",
    pass: "Ganli123",
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
        enum: ['הורה', 'גננת', 'admin'],
        required: true
    },
    phone: {
        type: String,
        required: true
    }
});

const GanSchema = new mongoose.Schema({
    notifications: [
        {
            text: {
                type: String,
                required: true
            }
        }
    ],
    createdBy: {
        type: String,
        required: true
    },
    ganName: {
        type: String,
        required: true
    },
    gordenName: {
        type: String,
        required: true
    },
    buildYear: {
        type: Number,
        required: true
    },
    NumOfkids: {
        type: Number,
        required: true
    },
    price: {
        type: String,
        required: true
    },
    address: {
        type: String,
        required: true
    },
    character: {
        type: String,
        enum: ['חילוני', 'דתי', 'ממלכתי'],
        required: true
    },
    maxKids: {
        type: Number,
        required: true
    },
    workTime: {
        type: String,
        required: true
    },
    vision: {
        type: String,
        required: true
    },
    principles: {
        type: String,
        required: true
    },
    approved: {
        type: Boolean,
        default: false
    },
    reviews: [
        {
            text: {
                type: String,
                required: true
            },
            author: {
                type: String,
                required: true
            }
        }
    ]
});

const collection = mongoose.model("users", LoginSchema);
const Gan = mongoose.model("gans", GanSchema);

module.exports = { collection, Gan };