const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const app = express();

// Base de datos SQLite
const db = new sqlite3.Database("./users.db");

// Crear tabla si no existe
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)`);

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: true
}));

// Ruta de registro
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    const hashedPass = await bcrypt.hash(password, 10);

    db.run(`INSERT INTO users(username, password) VALUES(?, ?)`,
        [username, hashedPass],
        (err) => {
            if (err) return res.send("El usuario ya existe.");
            res.send("Registrado correctamente. <a href='/'>Iniciar sesión</a>");
        }
    );
});

// Ruta de login
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (!user) return res.send("Usuario no encontrado");

        const valid = await bcrypt.compare(password, user.password);

        if (!valid) return res.send("Contraseña incorrecta");

        req.session.username = username;
        res.send("Sesión iniciada. <a href='/panel'>Ir al panel</a>");
    });
});

// Panel privado
app.get("/panel", (req, res) => {
    if (!req.session.username) return res.send("No has iniciado sesión.");
    res.send(`Bienvenido ${req.session.username}! <a href="/logout">Cerrar sesión</a>`);
});

// Cerrar sesión
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.listen(3000, () => {
    console.log("Servidor iniciado en http://localhost:3000");
});
