const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = 3000;
const JWT_SECRET = "clave_secreta_super_segura_123"; // Cambia esto en producción

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, "src")));

// Conexión a MySQL
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "123",
  database: "empresa"
});

db.connect(err => {
  if (err) {
    console.error("Error de conexión a la base de datos:", err);
  } else {
    console.log("Conectado a MySQL");
  }
});

// Middleware de autenticación JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: "Acceso denegado" }); //token requerido
  
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ error: "Token inválido o expirado" });
  }
};

// Rutas de autenticación
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: "Usuario y contraseña requeridos" });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    db.query(
      "INSERT INTO usuarios (username, password) VALUES (?, ?)",
      [username, hashedPassword],
      (error) => {
        if (error) {
          if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: "El usuario ya existe" });
          }
          return res.status(500).json({ error: error.message });
        }
        res.status(201).json({ mensaje: "Usuario registrado exitosamente" });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Error al registrar usuario" });
  }
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.query(
    "SELECT * FROM usuarios WHERE username = ?",
    [username],
    async (error, results) => {
      if (error) return res.status(500).json({ error: error.message });
      if (results.length === 0) return res.status(400).json({ error: "Credenciales inválidas" });

      const user = results[0];
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(400).json({ error: "Credenciales inválidas" });

      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: "5h" }
      );

      res.json({ token });
    }
  );
});

// Ruta principal
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "src", "index.html"));
});

// Rutas protegidas de empleados
app.get("/empleados", verifyToken, (req, res) => {
  db.query("SELECT * FROM empleados", (error, results) => {
    error ? res.status(500).json({ error: error.message }) : res.json(results);
  });
});

app.get("/empleados/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  db.query("SELECT * FROM empleados WHERE id = ?", [id], (error, results) => {
    if (error) {
      res.status(500).json({ error: error.message });
    } else if (results.length === 0) {
      res.status(404).json({ mensaje: "Empleado no encontrado" });
    } else {
      res.json(results[0]);
    }
  });
});

app.post("/empleados", verifyToken, (req, res) => {
  const { nombre, puesto, salario } = req.body;
  
  if (!nombre || !puesto || !salario) {
    return res.status(400).json({ mensaje: "Todos los campos son obligatorios" });
  }

  db.query(
    "INSERT INTO empleados (nombre, puesto, salario) VALUES (?, ?, ?)",
    [nombre, puesto, salario],
    (error, result) => {
      if (error) {
        res.status(500).json({ error: error.message });
      } else {
        res.status(201).json({ mensaje: "Empleado agregado", id: result.insertId });
      }
    }
  );
});

app.post("/empleados/masivo", verifyToken, (req, res) => {
  const empleados = req.body;

  if (!Array.isArray(empleados) || empleados.length === 0) {
    return res.status(400).json({ mensaje: "Datos inválidos" });
  }

  const valores = empleados.map(({ nombre, puesto, salario }) => [nombre, puesto, salario]);
  
  db.query(
    "INSERT INTO empleados (nombre, puesto, salario) VALUES ?",
    [valores],
    (error, result) => {
      error ? res.status(500).json({ error: error.message }) 
           : res.status(201).json({ mensaje: `${result.affectedRows} empleados agregados` });
    }
  );
});

app.put("/empleados/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  const { nombre, puesto, salario } = req.body;

  if (!nombre || !puesto || !salario) {
    return res.status(400).json({ mensaje: "Todos los campos son obligatorios" });
  }

  db.query(
    "UPDATE empleados SET nombre = ?, puesto = ?, salario = ? WHERE id = ?",
    [nombre, puesto, salario, id],
    (error, result) => {
      if (error) {
        res.status(500).json({ error: error.message });
      } else if (result.affectedRows === 0) {
        res.status(404).json({ mensaje: "Empleado no encontrado" });
      } else {
        res.json({ mensaje: "Empleado actualizado" });
      }
    }
  );
});

app.delete("/empleados/:id", verifyToken, (req, res) => {
  const id = req.params.id;

  db.query("DELETE FROM empleados WHERE id = ?", [id], (error, result) => {
    if (error) {
      res.status(500).json({ error: error.message });
    } else if (result.affectedRows === 0) {
      res.status(404).json({ mensaje: "Empleado no encontrado" });
    } else {
      res.json({ mensaje: "Empleado eliminado" });
    }
  });
});

// Iniciar servidor
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor corriendo en http://0.0.0.0:${PORT}`);
});


//BASE DE DATOS TABLA USUARIOS
///CREATE TABLE usuarios (
  //id INT AUTO_INCREMENT PRIMARY KEY,
 // username VARCHAR(255) UNIQUE NOT NULL,
 // password VARCHAR(255) NOT NULL
//);

