require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const xlsx = require('xlsx');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');



const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'sua-chave-secreta-super-segura';

// Configuração do email
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
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
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      setor TEXT NOT NULL,
      emailGestor TEXT NOT NULL,
      isAdmin BOOLEAN DEFAULT 0,
      dataCadastro DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS registros (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuarioId INTEGER NOT NULL,
      tipo TEXT NOT NULL,
      timestamp DATETIME NOT NULL,
      FOREIGN KEY(usuarioId) REFERENCES usuarios(id)
    )`);
    
    // Criar admin padrão
    db.get("SELECT id FROM usuarios WHERE email = 'admin@ponto.com'", [], (err, row) => {
      if (!row) {
        const hashedPassword = bcrypt.hashSync('admin123', 10);
        db.run(
          "INSERT INTO usuarios (nome, email, password, setor, emailGestor, isAdmin) VALUES (?, ?, ?, ?, ?, ?)",
          ['Administrador', 'admin@ponto.com', hashedPassword, 'Administração', 'admin@ponto.com', 1]
        );
      }
    });
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
app.post('/api/auth/register', async (req, res) => {
  const { nome, email, password, setor, emailGestor } = req.body;
  
  if (!nome || !email || !password || !setor || !emailGestor) {
    return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
  }
  
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
    
    const userId = await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO usuarios (nome, email, password, setor, emailGestor) VALUES (?, ?, ?, ?, ?)",
        [nome, email, hashedPassword, setor, emailGestor],
        function(err) {
          if (err) reject(err);
          resolve(this.lastID);
        }
      );
    });
    
    // Enviar email de notificação
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: emailGestor,
      subject: 'Novo cadastro no sistema de ponto',
      html: `
        <h1>Novo funcionário cadastrado</h1>
        <p>Dados do novo funcionário:</p>
        <ul>
          <li><strong>Nome:</strong> ${nome}</li>
          <li><strong>Email:</strong> ${email}</li>
          <li><strong>Setor:</strong> ${setor}</li>
          <li><strong>Data de cadastro:</strong> ${new Date().toLocaleString()}</li>
        </ul>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(201).json({ message: 'Usuário cadastrado com sucesso' });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ message: 'Erro ao cadastrar usuário' });
  }
});

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
      { id: user.id, email: user.email, isAdmin: user.isAdmin },
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
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ message: 'Erro ao fazer login' });
  }
});

// Rotas de registros
app.post('/api/registros', authenticateToken, async (req, res) => {
  try {
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
        "INSERT INTO registros (usuarioId, tipo, timestamp) VALUES (?, ?, ?)",
        [req.user.id, tipo, timestamp],
        function(err) {
          if (err) reject(err);
          resolve(this.lastID);
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

app.get('/api/registros/hoje', authenticateToken, async (req, res) => {
  try {
    const hoje = new Date().toISOString().split('T')[0];
    
    const registros = await new Promise((resolve, reject) => {
      db.all(
        `SELECT id, tipo, timestamp 
         FROM registros 
         WHERE usuarioId = ? AND date(timestamp) = date(?)
         ORDER BY timestamp ASC`,
        [req.user.id, hoje],
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

app.get('/api/registros/usuario/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { startDate, endDate } = req.query;

    const registros = await new Promise((resolve, reject) => {
      db.all(
        `SELECT id, tipo, timestamp 
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

app.post('/api/registros/enviar-email', authenticateToken, async (req, res) => {
  try {
    const { userId, startDate, endDate, emailGestor } = req.body;

    // Buscar registros
    const registros = await new Promise((resolve, reject) => {
      db.all(
        `SELECT tipo, timestamp 
         FROM registros 
         WHERE usuarioId = ? 
         AND date(timestamp) BETWEEN date(?) AND date(?)
         ORDER BY timestamp ASC`,
        [userId, startDate, endDate],
        (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        }
      );
    });

    // Buscar dados do usuário
    const usuario = await new Promise((resolve, reject) => {
      db.get(
        "SELECT nome, email, setor FROM usuarios WHERE id = ?",
        [userId],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });

    // Calcular horas trabalhadas
    let totalMs = 0;
    let entradaAtual = null;
    
    for (const registro of registros) {
      if (registro.tipo === 'entrada') {
        entradaAtual = new Date(registro.timestamp).getTime();
      } else if (entradaAtual) {
        totalMs += (new Date(registro.timestamp).getTime() - entradaAtual);
        entradaAtual = null;
      }
    }
    
    const totalHoras = Math.floor(totalMs / (1000 * 60 * 60));
    const totalMinutos = Math.floor((totalMs % (1000 * 60 * 60)) / (1000 * 60));

    // Formatar registros para email
    const registrosFormatados = registros.map(reg => ({
      Tipo: reg.tipo === 'entrada' ? 'Entrada' : 'Saída',
      Data: new Date(reg.timestamp).toLocaleDateString('pt-BR'),
      Hora: new Date(reg.timestamp).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
    }));

    // Enviar email
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: emailGestor,
      subject: `Espelho de Ponto - ${usuario.nome}`,
      html: `
        <h1>Espelho de Ponto</h1>
        <h2>${usuario.nome}</h2>
        <p><strong>Setor:</strong> ${usuario.setor}</p>
        <p><strong>Período:</strong> ${new Date(startDate).toLocaleDateString('pt-BR')} à ${new Date(endDate).toLocaleDateString('pt-BR')}</p>
        <p><strong>Total de horas:</strong> ${String(totalHoras).padStart(2, '0')}:${String(totalMinutos).padStart(2, '0')}</p>
        
        <h3>Registros:</h3>
        <table border="1" cellpadding="5" cellspacing="0">
          <tr>
            <th>Tipo</th>
            <th>Data</th>
            <th>Hora</th>
          </tr>
          ${registrosFormatados.map(reg => `
            <tr>
              <td>${reg.Tipo}</td>
              <td>${reg.Data}</td>
              <td>${reg.Hora}</td>
            </tr>
          `).join('')}
        </table>
      `
    };

    await transporter.sendMail(mailOptions);
    
    res.json({ message: 'Espelho de ponto enviado com sucesso' });
  } catch (error) {
    console.error('Erro ao enviar espelho de ponto:', error);
    res.status(500).json({ message: 'Erro ao enviar espelho de ponto' });
  }
});

// Rota para servir o frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});