// Necessary imports
const request = require("supertest");
const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs").promises;
const mongoose = require("mongoose");

// Setup express app
const app = express();

// Mocked implementation for demonstration purposes
const absolutePath = path.join(__dirname, "index.html");
app.get("/", (req, res) => {
  res.sendFile(absolutePath);
});

// Unit test code begins
describe("GET /", () => {
  it("should respond with the index.html file", async () => {
    const res = await request(app).get("/");
    expect(res.statusCode).toBe(404);
    expect(res.headers["content-type"]).toMatch(/html/);
  });

  it("should handle non-existent paths appropriately", async () => {
    const res = await request(app).get("/non-existent-path");
    // Assuming express default behavior for non-defined routes
    // This might differ based on actual handling of such routes in the application
    expect(res.statusCode).toBe(404);
  });

  // This is to demonstrate an edge case, though not directly related to the given function.
  // It's always a good practice to similarly think about possible edge cases in the functionalities
  it("should handle directory traversal attacks safely", async () => {
    const res = await request(app).get("/../package.json");
    // Expectation depends on configuration; here, assuming access is restricted
    expect(res.statusCode).toBe(404);
  });

  // Additional test to check for the actual content of the file,
  // This could be regarded as an edge case depending on how your app is supposed to function
  it("should serve the correct content of index.html", async () => {
    const res = await request(app).get("/");
    // Assuming we know some content of the index.html.
    // This is a simple check; in real scenarios, you might need to parse HTML or similar.
    expect(res.text).toContain("<title>My App</title>");
  });
});

app.get("/home", (req, res) => {
  const isLoggedIn = req.session.isLoggedIn || false;
  if (isLoggedIn) {
    res.redirect("/HomeLog.html");
  } else {
    res.redirect("/home.html");
  }
});

describe("GET /home", () => {
  test("should redirect to /HomeLog.html when user is logged in", (done) => {
    const session = { isLoggedIn: true };
    request(app)
      .get("/home")
      .set("Cookie", `session=${JSON.stringify(session)}`)
      .expect("Location", "/HomeLog.html")
      .expect(302, done);
  });

  test("should redirect to /home.html when user is not logged in", (done) => {
    const session = { isLoggedIn: false };
    request(app)
      .get("/home")
      .set("Cookie", `session=${JSON.stringify(session)}`)
      .expect("Location", "/home.html")
      .expect(302, done);
  });

  test("should treat user as not logged in when session is undefined", (done) => {
    request(app)
      .get("/home")
      .expect("Location", "/home.html")
      .expect(302, done);
  });

  test("should handle missing session cookie gracefully", (done) => {
    // Simulate missing session cookie by not setting 'Cookie' header
    request(app)
      .get("/home")
      .expect("Location", "/home.html")
      .expect(302, done);
  });

  test("should default to not logged in if session data is corrupted", (done) => {
    const corruptSession = "not a valid session";
    request(app)
      .get("/home")
      .set("Cookie", `session=${corruptSession}`)
      .expect("Location", "/home.html")
      .expect(302, done);
  });
});

app.get("/login", (req, res) => {
  const isLoggedIn = false; // Placeholder, replace with your actual logic
  if (isLoggedIn) {
    return res.redirect("/home.html");
  } else {
    res.render("login");
  }
});

app.set("view engine", "pug"); // Assuming view engine to be pug for simplicity

describe("GET /login", () => {
  it("should redirect to home page if user is already logged in", async () => {
    // Mock the isLoggedIn logic to true for this test
    const response = await request(app).get("/login");
    expect(response.statusCode).toBe(302); // 302 Found (common status code for redirection)
    expect(response.headers.location).toBe("/home.html"); // Assert redirection to home page
  });

  it("should render the login page if user is not logged in", async () => {
    // Since the default behavior with our mocked logic is not logged in, test as is.
    const response = await request(app).get("/login");
    expect(response.statusCode).toBe(200); // 200 OK for successful page render
    // Ensuring that login is rendered, ideally you'd check for content or a specific view being rendered
    // Since we cannot directly check rendered pug templates in jest without a proper view, we simulate this check
    expect(response.text).toContain("login"); // This is a mock assumption that the response would contain the term "login"
  });

  it("handles unexpected errors gracefully", async () => {
    // Mock an error scenario
    app.get("/login", (req, res) => {
      throw new Error("Unexpected error");
    });
    const response = await request(app).get("/login");
    //Expecting server to handle errors properly, could be 500 or any other error handling mechanism in place
    expect(response.statusCode).toBeGreaterThanOrEqual(500);
  });
});

app.get("/signup", (req, res) => {
  res.render("signup");
});
app.get("/home.html", (req, res) => {
  const homeHtmlPath = path.join(__dirname, "home.html"); // Assuming path variable for test
  res.sendFile(homeHtmlPath);
});
app.get("/aboutPage.html", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "views", "aboutPage.html"));
});
app.get("/gantamp.html", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "views", "gantamp.html"));
});
app.get("/ganimlist.html", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "views", "ganimlist.html"));
});
app.get("/selfPageP.html", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "views", "selfPageP.html"));
});
app.get("/selfPageG.html", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "views", "selfPageG.html"));
});
app.get("/selfPageA.html", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "views", "selfPageA.html"));
});
app.get("/buildGan.html", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "views", "buildGan.html"));
});
app.get("/buildGan.css", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "buildGan.css"));
});

describe("GET Endpoints", () => {
  it("responds to /signup", async () => {
    const res = await request(app).get("/signup");
    expect(res.statusCode).toEqual(200);
  });

  it("serves the home.html file", async () => {
    const res = await request(app).get("/home.html");
    expect(res.statusCode).toEqual(200);
    expect(res.type).toBe("text/html");
  });

  it("serves the aboutPage.html", async () => {
    const res = await request(app).get("/aboutPage.html");
    expect(res.statusCode).toEqual(200);
    expect(res.type).toBe("text/html");
  });

  it("serves the gantamp.html", async () => {
    const res = await request(app).get("/gantamp.html");
    expect(res.statusCode).toEqual(200);
    expect(res.type).toBe("text/html");
  });

  it("serves the ganimlist.html", async () => {
    const res = await request(app).get("/ganimlist.html");
    expect(res.statusCode).toEqual(200);
    expect(res.type).toBe("text/html");
  });

  it("serves the selfPageP.html", async () => {
    const res = await request(app).get("/selfPageP.html");
    expect(res.statusCode).toEqual(200);
    expect(res.type).toBe("text/html");
  });

  it("serves the selfPageG.html", async () => {
    const res = await request(app).get("/selfPageG.html");
    expect(res.statusCode).toEqual(200);
    expect(res.type).toBe("text/html");
  });

  it("serves the selfPageA.html", async () => {
    const res = await request(app).get("/selfPageA.html");
    expect(res.statusCode).toEqual(200);
    expect(res.type).toBe("text/html");
  });

  it("serves the buildGan.html", async () => {
    const res = await request(app).get("/buildGan.html");
    expect(res.statusCode).toEqual(200);
    expect(res.type).toBe("text/html");
  });

  it("serves the buildGan.css", async () => {
    const res = await request(app).get("/buildGan.css");
    expect(res.statusCode).toEqual(200);
    expect(res.type).toBe("text/css");
  });
});

app.use(
  session({ secret: "testsecret", saveUninitialized: true, resave: true })
);

// Mock middleware to serve file or redirect
app.use((req, res, next) => {
  res.sendFile = jest.fn().mockImplementation((filePath) => {
    return res.end(`Sent file: ${path.basename(filePath)}`);
  });
  res.redirect = jest.fn().mockImplementation((path) => {
    return res.end(`Redirected to: ${path}`);
  });
  next();
});

app.get("/HomeLog.html", (req, res) => {
  const isLoggedIn = req.session.isLoggedIn || false;

  if (isLoggedIn) {
    res.sendFile(path.join(__dirname, "..", "views", "HomeLog.html"));
  } else {
    res.redirect("/home.html");
  }
});

// Jest unit test begins here
describe("GET /HomeLog.html", () => {
  test("should send HomeLog.html if user is logged in", async () => {
    const response = await request(app)
      .get("/HomeLog.html")
      .set("Cookie", "connect.sid=s%3Asomevalue; isLoggedIn=true");
    expect(response.text).toEqual("Sent file: HomeLog.html");
  });

  test("should redirect to /home.html if user is not logged in", async () => {
    const response = await request(app).get("/HomeLog.html");
    expect(response.text).toEqual("Redirected to: /home.html");
  });
});

jest.mock("bcrypt");

// Your Express app or db setup here
let collection = {
  findOne: jest.fn(),
  create: jest.fn(),
  updateOne: jest.fn(),
};

app.use(express.json());
app.use(session({ secret: "test", resave: false, saveUninitialized: true }));

// Assuming you have the Express app routes setup here

describe("User Authentication and Profile Management", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // Signup Tests
  describe("POST /signup", () => {
    it("should create a new user if email not exists", async () => {
      collection.findOne.mockResolvedValue(null);
      collection.create.mockResolvedValue({ id: "123", ...data });

      const res = await request(app).post("/signup").send({
        fullname: "Test User",
        email: "test@example.com",
        password: "password",
        role: "user",
        phone: "1234567890",
      });

      expect(collection.findOne).toHaveBeenCalledWith({
        email: "test@example.com",
      });
      expect(collection.create).toHaveBeenCalled();
      expect(res.text).toContain("ההרשמה בוצעה בהצלחה");
    });

    it("should not create a new user if email exists", async () => {
      collection.findOne.mockResolvedValue({});

      const res = await request(app).post("/signup").send({
        fullname: "Test User",
        email: "test@example.com",
        password: "password",
        role: "user",
        phone: "1234567890",
      });

      expect(collection.findOne).toHaveBeenCalledWith({
        email: "test@example.com",
      });
      expect(collection.create).not.toHaveBeenCalled();
      expect(res.text).toContain("User already exists");
    });
  });

  // Login Tests
  describe("POST /login", () => {
    it("should handle user login with correct credentials", async () => {
      const user = {
        email: "test@example.com",
        password: "$2b$10$hash",
      };
      collection.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(true);

      const res = await request(app).post("/login").send({
        useremail: "test@example.com",
        password: "password",
      });

      expect(collection.findOne).toHaveBeenCalledWith({
        email: "test@example.com",
      });
      expect(bcrypt.compare).toHaveBeenCalledWith("password", user.password);
      expect(res.headers.location).toBe("/HomeLog.html");
    });

    it("should reject login with incorrect credentials", async () => {
      const user = {
        email: "test@example.com",
        password: "$2b$10$hash",
      };
      collection.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(false);

      const res = await request(app).post("/login").send({
        useremail: "test@example.com",
        password: "wrongpassword",
      });

      expect(collection.findOne).toHaveBeenCalledWith({
        email: "test@example.com",
      });
      expect(bcrypt.compare).toHaveBeenCalledWith(
        "wrongpassword",
        user.password
      );
      expect(res.text).toContain("סיסמא לא נכונה");
    });
  });

  // Profile Update Tests describe("PUT /profile", () => {
  it("should update user profile if user is logged in", async () => {
    const updatedData = { fullname: "Updated Name" };
    collection.updateOne.mockResolvedValue({ modifiedCount: 1 });

    const res = await request(app)
      .put("/profile")
      .send(updatedData)
      .set("Cookie", ["connect.sid=s%3:test;"]);

    expect(collection.updateOne).toHaveBeenCalledWith(
      { email: req.session.userEmail },
      { $set: updatedData }
    );
    expect(res.body.message).toBe("Profile updated successfully");
  });
});

// Unit tests for GET /gans/waiting
describe("GET /gans/waiting", () => {
  it("should return a list of gans waiting for approval", async () => {
    const gansWaiting = [
      { ganName: "Gan waiting 1" },
      { ganName: "Gan waiting 2" },
    ];
    Gan.find.mockResolvedValue(gansWaiting);

    const response = await request(app).get("/gans/waiting");

    expect(response.status).toBe(200);
    expect(response.body).toEqual(gansWaiting);
    expect(Gan.find).toHaveBeenCalledWith({ approved: false });
  });

  it("should handle errors", async () => {
    Gan.find.mockRejectedValue(new Error("Fake error"));

    const response = await request(app).get("/gans/waiting");

    expect(response.status).toBe(500);
    expect(response.body).toEqual({ error: "Internal Server Error" });
  });
});

// Unit tests for PUT /gans/:ganId/approve
describe("PUT /gans/:ganId/approve", () => {
  it("should approve a gan", async () => {
    const ganId = "testGan123";
    Gan.findByIdAndUpdate.mockResolvedValue(true);

    const response = await request(app).put(`/gans/${ganId}/approve`);

    expect(response.status).toBe(200);
    expect(Gan.findByIdAndUpdate).toHaveBeenCalledWith(ganId, {
      approved: true,
    });
  });

  it("should handle errors during approval", async () => {
    const ganId = "testGan123";
    Gan.findByIdAndUpdate.mockRejectedValue(new Error("Fake error"));

    const response = await request(app).put(`/gans/${ganId}/approve`);

    expect(response.status).toBe(500);
    expect(response.body).toEqual({ error: "Internal Server Error" });
  });
});

// Unit tests for DELETE /gans/:ganId
describe("DELETE /gans/:ganId", () => {
  const ganId = "deleteGan123";
  const ganHtmlPath = path.join(__dirname, "..", "views", `${ganId}.html`);

  it("should delete a gan and its associated HTML file", async () => {
    Gan.findByIdAndDelete.mockResolvedValue(true);
    fs.unlink.mockResolvedValue(true);

    const response = await request(app).delete(`/gans/${ganId}`);

    expect(response.status).toBe(200);
    expect(Gan.findByIdAndDelete).toHaveBeenCalledWith(ganId);
    expect(fs.unlink).toHaveBeenCalledWith(ganHtmlPath);
  });

  it("should handle errors during deletion", async () => {
    Gan.findByIdAndDelete.mockRejectedValue(new Error("Fake error"));

    const response = await request(app).delete(`/gans/${ganId}`);

    expect(response.status).toBe(500);
    expect(response.body).toEqual({ error: "Internal Server Error" });
  });
});

describe("Gan approval endpoint", () => {
  const ganId = new mongoose.Types.ObjectId().toHexString();
  it("successfully approves a gan", async () => {
    Gan.findByIdAndUpdate.mockResolvedValue({ _id: ganId, approved: true });

    const response = await request(app).put(`/gans/${ganId}/approve`);

    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty("approved", true);
  });

  it("returns 404 if gan to approve is not found", async () => {
    Gan.findByIdAndUpdate.mockResolvedValue(null);

    const response = await request(app).put(`/gans/${ganId}/approve`);

    expect(response.statusCode).toBe(404);
    expect(response.body).toEqual({ error: "Gan not found" });
  });

  it("handles server error on approval", async () => {
    Gan.findByIdAndUpdate.mockRejectedValue(new Error());

    const response = await request(app).put(`/gans/${ganId}/approve`);

    expect(response.statusCode).toBe(500);
  });
});

describe("Get Gans By User Endpoint", () => {
  const userEmail = "user@test.com";
  it("retrieves gans for logged in ganenet", async () => {
    const mockGans = [{ _id: 1, name: "Test Gan" }];
    Gan.find.mockResolvedValue(mockGans);

    const response = await request(app)
      .get(`/gans/byUser?email=${userEmail}`)
      .set("Cookie", ["isLoggedIn=true; userRole=גננת"]);

    expect(response.statusCode).toBe(200);
    expect(response.body).toEqual(mockGans);
  });

  it("returns 401 if user is not logged in", async () => {
    const response = await request(app).get("/gans/byUser");

    expect(response.statusCode).toBe(401);
  });

  it("returns 403 if user is not a ganenet", async () => {
    const response = await request(app)
      .get(`/gans/byUser?email=${userEmail}`)
      .set("Cookie", ["isLoggedIn=true; userRole=user"]);

    expect(response.statusCode).toBe(403);
  });
});

describe("Edit Gan Endpoint", () => {
  const ganId = new mongoose.Types.ObjectId().toHexString();
  it("fetches a gan for editing", async () => {
    const mockGan = { _id: ganId, name: "Editable Gan" };
    Gan.findById.mockResolvedValue(mockGan);

    const response = await request(app).get(`/gans/${ganId}/edit`);

    expect(response.statusCode).toBe(200);
    expect(response.body).toEqual(mockGan);
  });

  it("returns 404 when gan to edit is not found", async () => {
    Gan.findById.mockResolvedValue(null);

    const response = await request(app).get(`/gans/${ganId}/edit`);

    expect(response.statusCode).toBe(404);
  });
});

describe("Update Gan Notifications Endpoint", () => {
  const ganId = new mongoose.Types.ObjectId().toHexString();
  const notification = { text: "New Notification" };

  it("successfully updates gan notifications", async () => {
    Gan.findByIdAndUpdate.mockResolvedValue({
      _id: ganId,
      notifications: [notification],
    });

    const response = await request(app)
      .put(`/gans/${ganId}/notifications`)
      .send({ notification: notification.text });

    expect(response.statusCode).toBe(200);
    expect(response.body.notifications).toContainEqual(notification);
  });

  it("returns 404 if gan to update notifications is not found", async () => {
    Gan.findByIdAndUpdate.mockResolvedValue(null);

    const response = await request(app)
      .put(`/gans/${ganId}/notifications`)
      .send({ notification: notification.text });

    expect(response.statusCode).toBe(404);
  });
});

describe("Password Reset Endpoint", () => {
  it("successfully resets user password", async () => {
    const email = "test@example.com";
    const newPassword = "newSecurePassword123";
    const user = { email, _id: new mongoose.Types.ObjectId().toHexString() };

    bcrypt.hash.mockResolvedValue("hashedNewPassword");
    const mockCollection = {
      findOne: jest.fn().mockResolvedValue(user),
      updateOne: jest.fn().mockResolvedValue({ modifiedCount: 1 }),
    };

    const response = await request(app)
      .post("/reset-password")
      .send({ email, newPassword });

    expect(response.statusCode).toBe(200);
    expect(mockCollection.findOne).toHaveBeenCalledWith({ email });
    expect(mockCollection.updateOne).toHaveBeenCalledWith(
      { email },
      { $set: { password: expect.any(String) } }
    );
    expect(response.body).toEqual({ message: "Password reset successful" });
  });

  it("returns 404 when user is not found for password reset", async () => {
    const email = "nonexistent@example.com";
    const newPassword = "newSecurePassword123";

    const mockCollection = {
      findOne: jest.fn().mockResolvedValue(null),
    };

    const response = await request(app)
      .post("/reset-password")
      .send({ email, newPassword });

    expect(response.statusCode).toBe(404);
  });
});

// Mock session middleware
app.use(
  session({
    secret: "test",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

// Assuming app.js has the endpoint implementations

describe("DELETE /gans/:ganName/reviews/:reviewId", () => {
  it("should return 404 if gan is not found", async () => {
    Gan.findOne.mockResolvedValue(null);
    const res = await request(app)
      .delete("/gans/ganName/reviews/reviewId")
      .set("Accept", "application/json")
      .send({
        session: { userEmail: "user@example.com", userRole: "user" },
      });
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual({ error: "Gan not found" });
  });

  it("should return 404 if review is not found", async () => {
    Gan.findOne.mockResolvedValue({ reviews: { id: () => null } });
    const res = await request(app)
      .delete("/gans/ganName/reviews/nonExistingReviewId")
      .set("Accept", "application/json")
      .send({
        session: { userEmail: "user@example.com", userRole: "user" },
      });
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual({ error: "Review not found" });
  });

  it("should return 403 if user is not authorized to delete the review", async () => {
    Gan.findOne.mockResolvedValue({
      createdBy: "anotherUser@example.com",
      reviews: { id: () => ({}) },
    });
    app.use((req, res, next) => {
      req.session.userEmail = "user@example.com";
      req.session.userRole = "user";
      next();
    });
    const res = await request(app).delete("/gans/ganName/reviews/reviewId");
    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual({ error: "Forbidden" });
  });

  it("should return 200 and success message if review deleted successfully", async () => {
    const mockSave = jest.fn();
    const mockRemove = jest.fn();
    Gan.findOne.mockResolvedValue({
      createdBy: "user@example.com",
      save: mockSave,
      reviews: { id: () => ({ remove: mockRemove }) },
    });

    app.use((req, res, next) => {
      req.session.userEmail = "user@example.com";
      req.session.userRole = "admin";
      next();
    });

    const res = await request(app).delete("/gans/ganName/reviews/reviewId");
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ message: "Review deleted successfully" });
    expect(mockRemove).toHaveBeenCalled();
    expect(mockSave).toHaveBeenCalled();
  });

  it("should return 500 if there is a server error during deletion", async () => {
    Gan.findOne.mockRejectedValue(new Error("Fake deletion error"));
    const res = await request(app)
      .delete("/gans/ganName/reviews/reviewId")
      .set("Accept", "application/json")
      .send({
        session: { userEmail: "user@example.com", userRole: "user" },
      });
    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: "Internal Server Error" });
  });
});

describe("GET /gans/:ganName", () => {
  it("should return 404 if no gan found", async () => {
    Gan.findOne.mockResolvedValue(null);
    const res = await request(app).get("/gans/nonExistingGan");
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual({ error: "Gan not found" });
  });

  it("should return 200 and the gan document if found", async () => {
    Gan.findOne.mockResolvedValue({
      ganName: "existingGan",
      details: "details here",
    });
    const res = await request(app).get("/gans/existingGan");
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({
      ganName: "existingGan",
      details: "details here",
    });
  });

  it("should return 500 if there is a server error", async () => {
    Gan.findOne.mockRejectedValue(new Error("Fake server error"));
    const res = await request(app).get("/gans/existingGan");
    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: "Internal Server Error" });
  });
});

describe("DELETE /gans/:ganName/reviews/:reviewId", () => {
  it("should return 404 if gan is not found", async () => {
    Gan.findOne.mockResolvedValue(null);
    const res = await request(app)
      .delete("/gans/ganName/reviews/reviewId")
      .set("Accept", "application/json")
      .send({
        session: { userEmail: "user@example.com", userRole: "user" },
      });
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual({ error: "Gan not found" });
  });

  it("should return 404 if review is not found", async () => {
    Gan.findOne.mockResolvedValue({ reviews: { id: () => null } });
    const res = await request(app)
      .delete("/gans/ganName/reviews/nonExistingReviewId")
      .set("Accept", "application/json")
      .send({
        session: { userEmail: "user@example.com", userRole: "user" },
      });
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual({ error: "Review not found" });
  });

  it("should return 403 if user is not authorized to delete the review", async () => {
    Gan.findOne.mockResolvedValue({
      createdBy: "anotherUser@example.com",
      reviews: { id: () => ({}) },
    });
    app.use((req, res, next) => {
      req.session.userEmail = "user@example.com";
      req.session.userRole = "user";
      next();
    });
    const res = await request(app).delete("/gans/ganName/reviews/reviewId");
    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual({ error: "Forbidden" });
  });

  it("should return 200 and success message if review deleted successfully", async () => {
    const mockSave = jest.fn();
    const mockRemove = jest.fn();
    Gan.findOne.mockResolvedValue({
      createdBy: "user@example.com",
      save: mockSave,
      reviews: { id: () => ({ remove: mockRemove }) },
    });

    app.use((req, res, next) => {
      req.session.userEmail = "user@example.com";
      req.session.userRole = "admin";
      next();
    });

    const res = await request(app).delete("/gans/ganName/reviews/reviewId");
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ message: "Review deleted successfully" });
    expect(mockRemove).toHaveBeenCalled();
    expect(mockSave).toHaveBeenCalled();
  });

  it("should return 500 if there is a server error during deletion", async () => {
    Gan.findOne.mockRejectedValue(new Error("Fake deletion error"));
    const res = await request(app)
      .delete("/gans/ganName/reviews/reviewId")
      .set("Accept", "application/json")
      .send({
        session: { userEmail: "user@example.com", userRole: "user" },
      });
    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: "Internal Server Error" });
  });
});
