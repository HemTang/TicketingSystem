// Import necessary modules
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import flash from "express-flash";

// Create an instance of Express app
const app = express();
const port = 3000; // Set your desired port
const saltRounds = 10;

// Middleware to parse JSON bodies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));

//session middleware
app.use(
  session({
    secret: "TOPSECRETWORD",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

//Flash messages middlewate
app.use(flash());
//Passport middleware
app.use(passport.initialize());
app.use(passport.session());

///setting up the PostgeSQL database

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "Ticket_s",
  password: "Hbt@45181",
  port: 5433,
});
db.connect();

// Define routes for tickets
app.get("/", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("index.ejs");
  } else {
    res.redirect("/login");
  }
});
app.get("/dashboard", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("dashboard.ejs");
  } else {
    res.redirect("/login");
  }
});
app.get("/a_ticket", async (req, res) => {
  if (req.isAuthenticated()) {
    const A_tickets = await db.query(
      "SELECT * FROM tickets WHERE assignedto=$1",
      [req.user.name]
    );
    res.render("a_ticket.ejs", { a_tickets: A_tickets.rows, user: req.user });
  } else {
    res.redirect("/login");
  }
});
app.get("/t_list", async (req, res) => {
  if (req.isAuthenticated()) {
    const result = await db.query(`SELECT * FROM tickets`);
    console.log(result.rows);
    res.render("t_list.ejs", { tickets: result.rows, user: req.user });
  } else {
    res.redirect("/login");
  }
});
app.get("/create_ticket", async (req, res) => {
  if (req.isAuthenticated()) {
    const ITUser = await db.query(`SELECT * FROM users WHERE role=$1`, [
      "IT Support",
    ]);
    console.log(ITUser.rows);
    res.render("create_ticket.ejs", { ITUser: ITUser.rows });
  } else {
    res.redirect("/login");
  }
});
app.get("/unassigned", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(
        `SELECT * FROM tickets WHERE assignedto IS NULL`
      );
      res.render("unassigned.ejs", {
        unassignedTickets: result.rows,
        user: req.user,
      });
    } catch (error) {
      console.error("Error fetching unassigned tickets:", error);
      res.status(500).send("Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/login", async (req, res) => {
  res.render("login.ejs");
});
app.get("/register", async (req, res) => {
  res.render("register.ejs");
});

//User authentication
app.post("/register", async (req, res) => {
  const { email, password, role, name } = req.body;
  try {
    const checkUser1 = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (checkUser1.rows.length > 0) {
      res.send("User already exists! Try login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password", err);
        } else {
          console.log("Hashed  password", hash);
          const newUser = await db.query(
            `INSERT INTO users (email,password,role,name) VALUES ($1,$2,$3,$4) RETURNING *`,
            [email, hash, role, name]
          );
          const user = newUser.rows[0];
          req.login(user, (err) => {
            console.log(err);
            res.redirect("/t_list");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
}); // Register a new user

//Creating new ticket
app.post("/create", async (req, res) => {
  const { title, description, priority, category, assignedto, incidentfor } =
    req.body;

  try {
    await db.query(
      "INSERT INTO tickets (title, description, priority, category, assignedto, incidentfor) VALUES ($1, $2, $3, $4, $5, $6)",
      [title, description, priority, category, assignedto, incidentfor]
    );
    res.redirect("/t_list");
  } catch (error) {
    console.error("Error while saving data:", error);
    res.status(500).send("Server Error");
  }
});

//Viewing ticket
app.get("/view/:id", async (req, res) => {
  const id = req.params.id;
  const result = await db.query(`SELECT * FROM tickets WHERE id=$1`, [id]);
  const act_ticket = await db.query(
    "SELECT a.id, a.activity_description as activity, a.ticket_id  FROM activities a JOIN tickets t ON a.ticket_id = t.id WHERE a.ticket_id = $1",
    [id]
  );
  console.log(act_ticket.rows);

  res.render("view.ejs", {
    ticket: result.rows[0],
    activities: act_ticket.rows,
    user: req.user,
  });
});

//view update form
app.get("/update/:id", async (req, res) => {
  const id = req.params.id;
  const result = await db.query(`SELECT * FROM tickets WHERE id=$1`, [id]);
  res.render("update.ejs", { ticket: result.rows[0] });
});

//updating ticket
app.put("/update/:id", async (req, res) => {
  const id = req.params.id;
  await db.query("UPDATE tickets SET ");
});

// Delete ticket
app.get("/delete/:id", async (req, res) => {
  const id = req.params.id;
  try {
    await db.query("DELETE FROM tickets WHERE id=$1", [id]);
    res.redirect("/t_list");
  } catch (error) {
    console.error("Error while deleting ticket and related activities:", error);
    res.status(500).send("Server Error");
  }
});

//Adding activity to ticket
app.post("/comment/:id", async (req, res) => {
  const ticket_id = req.params.id;
  const comment = req.body.comment;

  try {
    await db.query(
      "INSERT INTO activities (ticket_id, activity_description) VALUES ($1, $2)",
      [ticket_id, comment]
    );

    res.redirect(`/view/${ticket_id}`);
  } catch (error) {
    console.error("Error while saving data:", error);
    res.status(500).send("Server Error");
  }
});
//Delete ticket_comment
app.get("/delete_comment/:id", async (req, res) => {
  const id = req.params.id;
  const result = await db.query("SELECT * FROM activities WHERE  id=$1", [id]);
  await db.query("DELETE FROM activities  WHERE id=$1", [id]);
  console.log(result.rows[0].ticket_id);
  res.redirect(`/view/${result.rows[0].ticket_id}`);
});

// Login user
app.post(
  "/login_user",
  passport.authenticate("local", {
    successRedirect: "/t_list",
    failureRedirect: "/login",
  })
);

///passport strategy

// Passport middleware
passport.use(
  new Strategy(
    {
      usernameField: "email", // Assuming your login form uses 'email' as the username field
      passwordField: "password", // Assuming your login form uses 'password' as the password field
    },
    async function (email, password, done) {
      try {
        // Find the user by email in the database
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          email,
        ]);

        if (result.rows.length === 0) {
          // If user is not found, return false
          return done(null, false, { message: "User not found" });
        }

        const user = result.rows[0];
        const storedHashedPassword = user.password;

        // Compare the provided password with the hashed password stored in the database
        bcrypt.compare(password, storedHashedPassword, (err, passwordMatch) => {
          if (err) {
            // If there's an error, return the error
            return done(err);
          }

          if (!passwordMatch) {
            // If passwords do not match, return false
            return done(null, false, { message: "Incorrect password" });
          }

          // If passwords match, return the user
          return done(null, user);
        });
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Login user
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/t_list",
    failureRedirect: "/login",
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

///Middleware to authorization

function authorize(role) {
  return function (req, res, next) {
    if (req.isAuthenticated() && req.user.role === role) {
      return next();
    } else {
      res.status(403).send("Forbidden");
    }
  };
}

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
