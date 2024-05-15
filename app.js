const express = require("express");
const app = express();
const bodyParser = require('body-parser');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const auth = require("./auth.js");



// require database connection 
const dbConnect = require("./db/dbConnect");
const User = require("./db/userModel");

// execute database connection 
dbConnect();
// Curb Cores Error by adding a header here
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content, Accept, Content-Type, Authorization"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, PATCH, OPTIONS"
  );
  next();
});




// body parser configuration
app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (request, response, next) => {
  response.json({ message: "Hey! This is your server response!" });
  next();
});

//Creating a register 
// register endpoint
app.post("/register", (request, response) => {
  // hash the password
  bcrypt
    .hash(request.body.password, 10)
    .then((hashedPassword) => {
      // create a new user instance and collect the data
      const user = new User({
        email: request.body.email,
        password: hashedPassword,
      });

      // save the new user
      user
        .save()
        // return success if the new user is added to the database successfully
        .then((result) => {
          response.status(201).send({
            message: "User Created Successfully",
            result,
          });
        })
        // catch error if the new user wasn't added successfully to the database
        .catch((error) => {
          response.status(500).send({
            message: "Error creating user",
            error,
          });
        });
    })
    // catch error if the password hash isn't successful
    .catch((e) => {
      response.status(500).send({
        message: "Password was not hashed successfully",
        e,
      });
    });
});


//Checking the login page if the email exits. Login Auth:
// login endpoint
app.post("/login", async (request, response) => {
  try {
    // Check if email exists
    const user = await User.findOne({ email: request.body.email });

    if (!user) {
      return response.status(404).send({ message: "Email not found" });
    }

    // Compare the password entered and the hashed password found
    const passwordCheck = await bcrypt.compare(request.body.password, user.password);

    if (!passwordCheck) {
      // Passwords do not match
      return response.status(400).send({ message: "Invalid email or password" });
    }

    // Create JWT token
    const token = jwt.sign(
      {
        userId: user._id,
        userEmail: user.email,
      },
      "RANDOM-TOKEN",
      { expiresIn: "24h" }
    );

    // Return success response with token
    response.status(200).send({
      message: "Login Successful",
      email: user.email,
      token,
    });
  } catch (error) {
    // Handle unexpected errors
    console.error("Login error:", error);
    response.status(500).send({ message: "Internal Server Error" });
  }
});

//creating 2 end points
app.get("/free-endpoint", (request, response) => {
  response.json({ message: "You are free to access me anytime" });
});

// authentication endpoint to see the working
app.get("/auth-endpoint", (request, response) => {
  response.json({ message: "You are authorized to access me" });
});


// authentication endpoint
app.get("/auth-endpoint", auth, (request, response) => {
  response.json({ message: "You are authorized to access me" });
});


module.exports = app;
