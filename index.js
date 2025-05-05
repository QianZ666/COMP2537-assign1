require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime =1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret:node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
    cookie: {
      maxAge: expireTime
    }
  })
);

// home page route
app.get("/", (req, res) => {
  // console.log(req.session.authenticated);
  // if (req.session.authenticated) {
  //   console.log("当前用户是：", req.session.username);
  // }

    if (req.session.username) {
      var html = `
        Hello, ${req.session.username}!
        <form action='/members' method='get'>
          <button>Go to Members Area</button>
        </form>
        <form action='/logout' method='get'>
          <button>Logout</button>
        </form>
      `;
    } else {
      var html = `
        Welcome
        <form action='/signup' method='get'>
          <button>Sign Up</button>
        </form>
        <form action='/login' method='get'>
          <button>Log In</button>
        </form>
      `;
    }
    res.send(html);
  });

//nosql-injection
app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  //If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

// Signup routes
app.get("/signup", (req, res) => {
  var missingUserName = req.query.missingUserName;
  var missingEmail = req.query.missingEmail;
  var missingPassword = req.query.missingPassword;
  var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
  if (missingUserName) {
    html += "<br> Name is required";
  }
  if (missingEmail) {
    html += "<br> Email is required";
  }
  if (missingPassword) {
    html += "<br> Password is required";
  }
  res.send(html);
});
app.get("/login", (req, res) => {
  const error = req.query.error;
  let errorMessage = '';
  
  // More specific error messages
  if (error === 'invalid_credentials') {
    errorMessage = '<p style="color:red;">Invalid username or password</p>';
  } else if (error === 'missing_fields') {
    errorMessage = '<p style="color:red;">Please provide both username and password</p>';
  } else if (error === 'validation_error') {
    errorMessage = '<p style="color:red;">Invalid input format</p>';
  }

  res.send(`
    <h2>Login</h2>
    ${errorMessage}
    <form action='/loggingin' method='post'>
      <input name='username' type='text' placeholder='Username' value="${req.query.username || ''}"><br>
      <input name='password' type='password' placeholder='Password'><br>
      <button>Submit</button>
    </form>
    <p><a href='/login'>Try again</a></p>
  `);
});

// members route
app.get("/members", (req, res) => {
    if (!req.session.username){
        return res.redirect('/');
    }
    const images = ['cat-1.gif','cat2.gif','cat3.gif'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    var html =`
      Hello, ${req.session.username}!
      <img src='/${randomImage}' style='width:250px;'>
      <a href = '/logout'>Logout</a>
      `;
      res.send(html);
    
});

//logout route
app.get("/logout", (req, res) => {
  req.session.destroy();
  var html = `
    You are logged out.
    <a href = '/'> Rerurn to Home</a>
    `;
  res.send(html);
});


// Submit User route 
app.post("/submitUser", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const email = req.body.email;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const { error } = schema.validate(
    { username, email, password },
    { abortEarly: false }
  );

  if (error) {
    const query = [];
    for (const detail of error.details) {
      if (detail.context.key === "username") query.push("missingUserName=true");
      if (detail.context.key === "email") query.push("missingEmail=true");
      if (detail.context.key === "password") query.push("missingPassword=true");
    }
    res.redirect("/signup?" + query.join("&"));
    return;
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({ username, email, password: hashedPassword });

  res.send("Successfully created user");
});

app.post("/loggingin", async (req, res) => {
  const { username, password } = req.body;

  // Joi validation schema
  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().min(3).max(20).required()
  });

  // Validate inputs
  const validationResult = schema.validate({ username, password });
  if (validationResult.error) {
    return res.redirect('/login?error=validation_error&username=' + encodeURIComponent(username));
  }

  // Find user
  const user = await userCollection.findOne({ username });
  if (!user) {
    return res.redirect('/login?error=invalid_credentials&username=' + encodeURIComponent(username));
  }

  // Verify password
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.redirect('/login?error=invalid_credentials&username=' + encodeURIComponent(username));
  }

  // Create session
  req.session.authenticated = true;
  req.session.username = username;
  req.session.email = user.email;
  res.redirect("/members");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
