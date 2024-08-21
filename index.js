import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import flash from "connect-flash";
import { renderFile } from "ejs";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();
let books = [];
let users=[];
let currentUserId;
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
// Initialize flash middleware
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());



 
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Middleware to check authentication
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
}

// index page route
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/home");
  } else {
    res.render("index.ejs");
  }
});

app.get("/login", (req, res) => {
  const messages = req.flash('error');
  res.render("login.ejs", { messages });
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// Home page route (protected)
app.get("/home", ensureAuthenticated, async (req, res) => {

console.log(req.user.id);

  try {
    const result = await db.query("SELECT * FROM book WHERE user_id=$1",[req.user.id]);
    books = result.rows;
    res.render("home.ejs", { books });
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred while fetching books.");
  }
});

// Add new book page
app.get("/addNew", ensureAuthenticated, (req, res) => {
  res.render("addNew.ejs");
});

// Logout route
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// Book detail route
app.get('/detail/:id', async (req, res) => {
  try {
    const bookId = parseInt(req.params.id);
    console.log('Book ID:', bookId);
    const result = await db.query('SELECT * FROM book WHERE id = $1 AND user_id = $2', [bookId, req.user.id]);
    if (result.rows.length > 0) {
      res.render('bookDetail.ejs', { book: result.rows[0] });
    } else {
      res.status(404).send('Book not found');
    }
  } catch (err) {
    console.error('Error fetching book details:', err);
    res.status(500).send('Server Error');
  }
});


// Register route
app.post("/register", async (req, res) => {
  const { userName: name, userEmail: email, userPassword: password } = req.body;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.status(500).send("Server error");
        } else {
          const result = await db.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
            [name, email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error("Login error:", err);
              res.status(500).send("Login error");
            } else {
              res.redirect("/home");
            }
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

// Login route
app.post("/login", passport.authenticate("local", {
  successRedirect: "/home",
  failureRedirect: "/login",
  failureFlash: true,
}));

// Add new book route
app.post("/add", async (req, res) => {
 
  const { title, author, status, rate, notes } = req.body;
  if (title.length === 0 || author.length === 0 || status.length === 0) {
    console.log("Complete the fields");
    res.redirect("/addNew");
  } else {
    try {
      await db.query("INSERT INTO book (title, author, status, rate, notes,user_id) VALUES ($1, $2, $3, $4, $5,$6)", [title, author, status, rate, notes,req.user.id]);
      res.redirect("/addNew");
    } catch (err) {
      console.log(err);
      res.status(500).send("An error occurred while adding the book.");
    }
  }
});

// Edit book route
app.post("/edit", async (req, res) => {
  const { updatedBookId: id, title, author, status, rate, notes } = req.body;
  try {
    await db.query("UPDATE book SET title = $1, author = $2, status = $3, rate = $4, notes = $5 WHERE id = $6", [title, author, status, rate, notes, id]);
    res.redirect("/home");
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred while editing the book.");
  }
});

// Delete book route
app.post("/delete", async (req, res) => {
  const { deletedBookId: id } = req.body;
  try {
    await db.query("DELETE FROM book WHERE id = $1", [id]);
    res.redirect("/home");
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred while deleting the book.");
  }
});

passport.use(
  "local",
  new Strategy(
    {
      usernameField: "userEmail",
      passwordField: "userPassword",
    },
    async function (userEmail, userPassword, cb) {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [userEmail]);
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;
          bcrypt.compare(userPassword, storedHashedPassword, (err, valid) => {
            if (err) {
              console.error("Error comparing passwords:", err);
              return cb(err);
            }
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false, { message: 'Incorrect password.' });
            }
          });
        } else {
          return cb(null, false, { message: 'User not found.' });
        }
      } catch (err) {
        console.error("Error during authentication:", err);
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on ${port}`);
});
