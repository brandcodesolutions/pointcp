require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'sua-chave-secreta-super-segura';

// Configuração do email
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // true para 465, false para outras portas
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Configuração do banco de dados
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados:', err);
  } else {
    console.log('Conectado ao banco de dados SQLite');
    initializeDatabase();
  }
});

function initializeDatabase() {
  db.serialize(() => {
    // Primeiro verifica se a tabela existe
    db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'", (err, row) => {
      if (err) {
        console.error('Erro ao verificar tabela usuarios:', err);
        return;
      }

      if (row) {
        // Se a tabela existe, verifica se a coluna isGestor existe
        db.all("PRAGMA table_info(usuarios)", (err, columns) => {
          if (err) {
            console.error('Erro ao verificar colunas:', err);
            return;
          }

          // Verifica se a coluna isGestor existe
          const hasIsGestor = columns.some(col => col.name === 'isGestor');
          
          if (!hasIsGestor) {
            // Adiciona a coluna se não existir
            db.run("ALTER TABLE usuarios ADD COLUMN isGestor BOOLEAN DEFAULT 0", (err) => {
              if (err) {
                console.error('Erro ao adicionar coluna isGestor:', err);
              } else {
                console.log('Coluna isGestor adicionada com sucesso');
              }
            });
          }
        });
      } else {
        // Cria a tabela se não existir
        db.run(`CREATE TABLE usuarios (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          nome TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          setor TEXT NOT NULL,
          emailGestor TEXT NOT NULL,
          isGestor BOOLEAN DEFAULT 0,
          latitude REAL,
          longitude REAL,
          raioPermitido INTEGER DEFAULT 100,
          dataCadastro DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
          if (err) {
            console.error('Erro ao criar tabela usuarios:', err);
          } else {
            console.log('Tabela usuarios criada com sucesso');
          }
        });
      }
    });

    // Cria a tabela de registros se não existir
    db.run(`CREATE TABLE IF NOT EXISTS registros (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuarioId INTEGER NOT NULL,
      tipo TEXT NOT NULL,
      timestamp DATETIME NOT NULL,
      latitude REAL,
      longitude REAL,
      FOREIGN KEY(usuarioId) REFERENCES usuarios(id)
    )`);
  });
}

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Middleware de autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Rotas de autenticação
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await new Promise((resolve, reject) => {
      db.get("SELECT * FROM usuarios WHERE email = ?", [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    
    if (!user) return res.status(401).json({ message: 'Credenciais inválidas' });
    
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ message: 'Credenciais inválidas' });
    
    const token = jwt.sign(
      { id: user.id, email: user.email, isGestor: user.isGestor },
      SECRET_KEY,
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      user: {
        id: user.id,
        nome: user.nome,
        email: user.email,
        setor: user.setor,
        isGestor: user.isGestor,
        latitude: user.latitude,
        longitude: user.longitude,
        raioPermitido: user.raioPermitido
      }
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ message: 'Erro ao fazer login' });
  }
});

app.post('/api/auth/login-gestor', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await new Promise((resolve, reject) => {
      db.get("SELECT * FROM usuarios WHERE email = ? AND isGestor = 1", [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    
    if (!user) return res.status(401).json({ message: 'Gestor não encontrado' });
    
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ message: 'Credenciais inválidas' });
    
    const token = jwt.sign(
      { id: user.id, email: user.email, isGestor: true },
      SECRET_KEY,
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token,
      user: {
        id: user.id,
        nome: user.nome,
        email: user.email,
        isGestor: true
      }
    });
  } catch (error) {
    console.error('Erro no login do gestor:', error);
    res.status(500).json({ message: 'Erro ao fazer login' });
  }
});

app.post('/api/auth/register-gestor', async (req, res) => {
  // Verificar se já existe algum gestor cadastrado
  const gestorExistente = await new Promise((resolve) => {
    db.get("SELECT id FROM usuarios WHERE isGestor = 1 LIMIT 1", (err, row) => resolve(row));
  });

  if (gestorExistente) {
    return res.status(403).json({ 
      message: 'Cadastro de gestor bloqueado. Acesse com um gestor existente.' 
    });
  }

  // Processar cadastro do primeiro gestor
  const { nome, email, password } = req.body;
  
  // Validações básicas
  if (!nome || !email || !password) {
    return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: 'A senha deve ter no mínimo 8 caracteres' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ message: 'E-mail inválido' });
  }

  try {
    // Verificar se o e-mail já está cadastrado (mesmo que não seja gestor)
    const userExists = await new Promise((resolve, reject) => {
      db.get("SELECT id FROM usuarios WHERE email = ?", [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    
    if (userExists) {
      return res.status(400).json({ message: 'E-mail já cadastrado' });
    }
    
    // Criptografar a senha
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Cadastrar o primeiro gestor
    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO usuarios (nome, email, password, setor, emailGestor, isGestor) VALUES (?, ?, ?, ?, ?, ?)",
        [nome, email, hashedPassword, 'Gestão', email, 1],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });
    
    // Enviar e-mail de confirmação
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Cadastro de Gestor realizado com sucesso',
      html: `
        <h1>Bem-vindo ao Sistema de Ponto</h1>
        <p>Seu cadastro como gestor foi realizado com sucesso.</p>
        <p><strong>Credenciais de acesso:</strong></p>
        <ul>
          <li><strong>Email:</strong> ${email}</li>
        </ul>
        <p>Acesse o sistema em: ${process.env.APP_URL || 'http://localhost:3000'}</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(201).json({ 
      success: true,
      message: 'Gestor cadastrado com sucesso. Você já pode fazer login.' 
    });
  } catch (error) {
    console.error('Erro no registro do gestor:', error);
    res.status(500).json({ 
      success: false,
      message: 'Erro ao cadastrar gestor' 
    });
  }
});

app.post('/api/colaboradores', authenticateToken, async (req, res) => {
  if (!req.user.isGestor) {
    return res.status(403).json({ message: 'Apenas gestores podem cadastrar colaboradores' });
  }

  const { nome, email, setor, latitude, longitude, raioPermitido } = req.body;
  const password = Math.random().toString(36).slice(-8);

  try {
    const userExists = await new Promise((resolve, reject) => {
      db.get("SELECT id FROM usuarios WHERE email = ?", [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    
    if (userExists) {
      return res.status(400).json({ message: 'E-mail já cadastrado' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO usuarios (nome, email, password, setor, emailGestor, latitude, longitude, raioPermitido) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [nome, email, hashedPassword, setor, req.user.email, latitude, longitude, raioPermitido || 100],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });

    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Seu cadastro no Sistema de Ponto',
      html: `
        <h1>Bem-vindo ao Sistema de Ponto</h1>
        <p>Você foi cadastrado como colaborador.</p>
        <p><strong>Credenciais de acesso:</strong></p>
        <ul>
          <li><strong>Email:</strong> ${email}</li>
          <li><strong>Senha temporária:</strong> ${password}</li>
        </ul>
        <p>Acesse o sistema em: ${process.env.APP_URL || 'http://localhost:3000'}</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(201).json({ message: 'Colaborador cadastrado com sucesso' });
  } catch (error) {
    console.error('Erro ao cadastrar colaborador:', error);
    res.status(500).json({ message: 'Erro ao cadastrar colaborador' });
  }
});

// Rotas de registros
app.post('/api/registros', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    
    if (!latitude || !longitude) {
      return res.status(400).json({ message: 'Localização é obrigatória' });
    }

    const usuario = await new Promise((resolve, reject) => {
      db.get("SELECT latitude, longitude, raioPermitido FROM usuarios WHERE id = ?", 
        [req.user.id], (err, row) => {
          if (err) reject(err);
          resolve(row);
      });
    });

    if (!usuario.latitude || !usuario.longitude) {
      return res.status(400).json({ message: 'Localização não configurada' });
    }

    const distance = await calcularDistancia(
      latitude,
      longitude, 
      usuario.latitude, 
      usuario.longitude
    );

    if (distance > (usuario.raioPermitido || 100)) {
      return res.status(400).json({ 
        message: `Fora do local permitido (${Math.round(distance)}m do ponto)` 
      });
    }

    const lastRecord = await new Promise((resolve, reject) => {
      db.get(
        "SELECT tipo FROM registros WHERE usuarioId = ? ORDER BY timestamp DESC LIMIT 1",
        [req.user.id],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });
    
    const tipo = lastRecord?.tipo === 'entrada' ? 'saida' : 'entrada';
    const timestamp = new Date().toISOString();
    
    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO registros (usuarioId, tipo, timestamp, latitude, longitude) VALUES (?, ?, ?, ?, ?)",
        [req.user.id, tipo, timestamp, latitude, longitude],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });
    
    res.status(201).json({ 
      message: `Ponto ${tipo === 'entrada' ? 'registrado' : 'registrado'} com sucesso`,
      tipo 
    });
  } catch (error) {
    console.error('Erro ao registrar ponto:', error);
    res.status(500).json({ message: 'Erro ao registrar ponto' });
  }
});

async function calcularDistancia(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const φ1 = lat1 * Math.PI/180;
  const φ2 = lat2 * Math.PI/180;
  const Δφ = (lat2-lat1) * Math.PI/180;
  const Δλ = (lon2-lon1) * Math.PI/180;

  const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
            Math.cos(φ1) * Math.cos(φ2) *
            Math.sin(Δλ/2) * Math.sin(Δλ/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

  return R * c;
}

// Rotas do gestor
app.get('/api/colaboradores', authenticateToken, async (req, res) => {
  if (!req.user.isGestor) {
    return res.status(403).json({ message: 'Apenas gestores podem acessar esta lista' });
  }

  try {
    const colaboradores = await new Promise((resolve, reject) => {
      db.all(
        "SELECT id, nome, email, setor FROM usuarios WHERE emailGestor = ? AND isGestor = 0",
        [req.user.email],
        (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        }
      );
    });

    res.json({ colaboradores });
  } catch (error) {
    console.error('Erro ao buscar colaboradores:', error);
    res.status(500).json({ message: 'Erro ao buscar colaboradores' });
  }
});

app.get('/api/registros/colaborador/:id', authenticateToken, async (req, res) => {
  if (!req.user.isGestor) {
    return res.status(403).json({ message: 'Apenas gestores podem acessar estes registros' });
  }

  try {
    const { id } = req.params;
    const { startDate, endDate } = req.query;

    const registros = await new Promise((resolve, reject) => {
      db.all(
        `SELECT id, tipo, timestamp, latitude, longitude 
         FROM registros 
         WHERE usuarioId = ? 
         AND date(timestamp) BETWEEN date(?) AND date(?)
         ORDER BY timestamp ASC`,
        [id, startDate, endDate],
        (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        }
      );
    });

    res.json({ registros });
  } catch (error) {
    console.error('Erro ao buscar registros:', error);
    res.status(500).json({ message: 'Erro ao buscar registros' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});