require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const path = require('path');
const moment = require('moment');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'sua-chave-secreta-super-segura';

// Configuração do email
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
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
    // Tabela de usuários
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
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
      jornadaDiaria INTEGER DEFAULT 8,
      dataCadastro DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabela de registros
    db.run(`CREATE TABLE IF NOT EXISTS registros (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuarioId INTEGER NOT NULL,
      tipo TEXT NOT NULL,
      timestamp DATETIME NOT NULL,
      latitude REAL,
      longitude REAL,
      justificado BOOLEAN DEFAULT 0,
      motivoJustificativa TEXT,
      FOREIGN KEY(usuarioId) REFERENCES usuarios(id)
    )`);

    // Tabela de configurações
    db.run(`CREATE TABLE IF NOT EXISTS config (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      horasDiarias INTEGER DEFAULT 8,
      intervaloMinimo INTEGER DEFAULT 60,
      toleranciaAtraso INTEGER DEFAULT 10,
      horaExtraMinima INTEGER DEFAULT 15
    )`);

    // Tabela de justificativas
    db.run(`CREATE TABLE IF NOT EXISTS justificativas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuarioId INTEGER NOT NULL,
      data TEXT NOT NULL,
      horario TEXT NOT NULL,
      tipo TEXT NOT NULL,
      motivo TEXT NOT NULL,
      status TEXT DEFAULT 'pendente',
      motivoRejeicao TEXT,
      FOREIGN KEY(usuarioId) REFERENCES usuarios(id)
    )`);

    // Inserir configuração padrão se não existir
    db.get("SELECT id FROM config LIMIT 1", (err, row) => {
      if (!row) {
        db.run(`INSERT INTO config (
          horasDiarias, intervaloMinimo, toleranciaAtraso, horaExtraMinima
        ) VALUES (8, 60, 10, 15)`);
      }
    });

    // Inserir usuário admin padrão se não existir
    db.get("SELECT id FROM usuarios WHERE isGestor = 1 LIMIT 1", (err, row) => {
      if (!row) {
        const senhaPadrao = 'Admin@123';
        bcrypt.hash(senhaPadrao, 10, (err, hash) => {
          db.run(
            "INSERT INTO usuarios (nome, email, password, setor, emailGestor, isGestor) VALUES (?, ?, ?, ?, ?, ?)",
            ['Administrador', 'admin@empresa.com', hash, 'Administração', 'admin@empresa.com', 1]
          );
        });
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
        raioPermitido: user.raioPermitido,
        jornadaDiaria: user.jornadaDiaria || 8
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
  const { nome, email, password } = req.body;
  
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
        "INSERT INTO usuarios (nome, email, password, setor, emailGestor, isGestor) VALUES (?, ?, ?, ?, ?, ?)",
        [nome, email, hashedPassword, 'Gestão', email, 1],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });
    
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

// Rotas de colaboradores
app.post('/api/colaboradores', authenticateToken, async (req, res) => {
  if (!req.user.isGestor) {
    return res.status(403).json({ success: false, message: 'Apenas gestores podem cadastrar colaboradores' });
  }

  const { nome, email, setor, password, latitude, longitude, raioPermitido, jornadaDiaria } = req.body;

  if (!nome || !email || !setor || !password || !latitude || !longitude) {
    return res.status(400).json({ 
      success: false, 
      message: 'Todos os campos são obrigatórios' 
    });
  }

  if (password.length < 8) {
    return res.status(400).json({ 
      success: false, 
      message: 'A senha deve ter no mínimo 8 caracteres' 
    });
  }

  try {
    const userExists = await new Promise((resolve, reject) => {
      db.get("SELECT id FROM usuarios WHERE email = ?", [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    
    if (userExists) {
      return res.status(400).json({ 
        success: false, 
        message: 'E-mail já cadastrado' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO usuarios 
        (nome, email, password, setor, emailGestor, latitude, longitude, raioPermitido, jornadaDiaria) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          nome, 
          email, 
          hashedPassword, 
          setor, 
          req.user.email,
          parseFloat(latitude),
          parseFloat(longitude),
          parseInt(raioPermitido) || 100,
          parseInt(jornadaDiaria) || 8
        ],
        function(err) {
          if (err) reject(err);
          resolve(this.lastID);
        }
      );
    });

    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Cadastro no Sistema de Ponto',
      html: `
        <h1>Bem-vindo ao Sistema de Ponto</h1>
        <p>Você foi cadastrado como colaborador por ${req.user.email}.</p>
        <p><strong>Seus dados de acesso:</strong></p>
        <ul>
          <li><strong>Email:</strong> ${email}</li>
          <li><strong>Senha:</strong> ${password}</li>
        </ul>
        <p>Acesse o sistema em: ${process.env.APP_URL || 'http://localhost:3000'}</p>
      `
    };

    try {
      await transporter.sendMail(mailOptions);
    } catch (emailError) {
      console.error('Erro ao enviar e-mail:', emailError);
    }

    res.status(201).json({ 
      success: true,
      message: 'Colaborador cadastrado com sucesso' 
    });

  } catch (error) {
    console.error('Erro ao cadastrar colaborador:', error);
    res.status(500).json({ 
      success: false,
      message: 'Erro ao cadastrar colaborador' 
    });
  }
});

app.get('/api/colaboradores', authenticateToken, async (req, res) => {
  if (!req.user.isGestor) {
    return res.status(403).json({ message: 'Apenas gestores podem acessar esta lista' });
  }

  try {
    const colaboradores = await new Promise((resolve, reject) => {
      db.all(
        "SELECT id, nome, email, setor, jornadaDiaria FROM usuarios WHERE emailGestor = ? AND isGestor = 0 ORDER BY nome",
        [req.user.email],
        (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        }
      );
    });

    res.json({ success: true, colaboradores });
  } catch (error) {
    console.error('Erro ao buscar colaboradores:', error);
    res.status(500).json({ success: false, message: 'Erro ao buscar colaboradores' });
  }
});

// Rotas de registros
app.post('/api/registros', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    
    if (!latitude || !longitude) {
      return res.status(400).json({ success: false, message: 'Localização é obrigatória' });
    }

    const usuario = await new Promise((resolve, reject) => {
      db.get("SELECT latitude, longitude, raioPermitido FROM usuarios WHERE id = ?", 
        [req.user.id], (err, row) => {
          if (err) reject(err);
          resolve(row);
      });
    });

    if (!usuario.latitude || !usuario.longitude) {
      return res.status(400).json({ success: false, message: 'Localização não configurada' });
    }

    const distance = calcularDistancia(
      parseFloat(latitude),
      parseFloat(longitude), 
      parseFloat(usuario.latitude), 
      parseFloat(usuario.longitude)
    );

    if (distance > (usuario.raioPermitido || 100)) {
      return res.status(400).json({ 
        success: false,
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
    
    let tipo = 'entrada';
    if (lastRecord) {
      if (lastRecord.tipo === 'entrada') {
        const registrosHoje = await new Promise((resolve, reject) => {
          db.all(
            "SELECT tipo, timestamp FROM registros WHERE usuarioId = ? AND date(timestamp) = date('now') ORDER BY timestamp",
            [req.user.id],
            (err, rows) => {
              if (err) reject(err);
              resolve(rows);
            }
          );
        });
        
        let horasTrabalhadas = 0;
        let entradaAtual = null;
        
        for (const registro of registrosHoje) {
          if (registro.tipo === 'entrada') {
            entradaAtual = new Date(registro.timestamp).getTime();
          } else if (entradaAtual) {
            horasTrabalhadas += (new Date(registro.timestamp).getTime() - entradaAtual);
            entradaAtual = null;
          }
        }
        
        horasTrabalhadas = horasTrabalhadas / (1000 * 60 * 60);
        
        if (horasTrabalhadas >= 6) {
          tipo = 'intervalo';
        } else {
          tipo = 'saida';
        }
      } else if (lastRecord.tipo === 'intervalo') {
        tipo = 'entrada';
      } else {
        tipo = 'entrada';
      }
    }
    
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
      success: true,
      message: `Ponto ${tipo === 'entrada' ? 'registrado' : 'registrado'} com sucesso`,
      tipo 
    });
  } catch (error) {
    console.error('Erro ao registrar ponto:', error);
    res.status(500).json({ success: false, message: 'Erro ao registrar ponto' });
  }
});

app.post('/api/registros/justificar', authenticateToken, async (req, res) => {
  try {
    const { data, horario, tipo, motivo } = req.body;
    
    if (!data || !horario || !tipo || !motivo) {
      return res.status(400).json({ success: false, message: 'Todos os campos são obrigatórios' });
    }
    
    const dataHora = moment(`${data}T${horario}`);
    if (dataHora.isAfter(moment())) {
      return res.status(400).json({ success: false, message: 'Não é possível justificar pontos futuros' });
    }
    
    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO justificativas (usuarioId, data, horario, tipo, motivo) VALUES (?, ?, ?, ?, ?)",
        [req.user.id, data, horario, tipo, motivo],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });
    
    res.status(201).json({ 
      success: true,
      message: 'Justificativa enviada com sucesso. Aguarde aprovação do gestor.'
    });
  } catch (error) {
    console.error('Erro ao registrar justificativa:', error);
    res.status(500).json({ success: false, message: 'Erro ao registrar justificativa' });
  }
});

app.get('/api/registros/hoje', authenticateToken, async (req, res) => {
  try {
    const registros = await new Promise((resolve, reject) => {
      db.all(
        "SELECT id, tipo, timestamp, latitude, longitude, justificado FROM registros WHERE usuarioId = ? AND date(timestamp) = date('now') ORDER BY timestamp",
        [req.user.id],
        (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        }
      );
    });

    let totalHoras = 0;
    let horasExtras = 0;
    let entradaAtual = null;
    
    for (const registro of registros) {
      if (registro.tipo === 'entrada') {
        entradaAtual = new Date(registro.timestamp).getTime();
      } else if (entradaAtual) {
        const horasDia = (new Date(registro.timestamp).getTime() - entradaAtual);
        totalHoras += horasDia;
        
        const jornadaDiaria = 8 * 60 * 60 * 1000;
        if (horasDia > jornadaDiaria) {
          horasExtras += (horasDia - jornadaDiaria);
        }
        
        entradaAtual = null;
      }
    }
    
    const formatHours = (ms) => {
      const horas = Math.floor(ms / (1000 * 60 * 60));
      const minutos = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
      return `${String(horas).padStart(2, '0')}:${String(minutos).padStart(2, '0')}`;
    };

    res.json({ 
      success: true, 
      registros,
      horasTrabalhadas: formatHours(totalHoras),
      horasExtras: formatHours(horasExtras),
      bancoHoras: formatHours(horasExtras)
    });
  } catch (error) {
    console.error('Erro ao buscar registros:', error);
    res.status(500).json({ success: false, message: 'Erro ao buscar registros' });
  }
});

app.post('/api/registros/enviar-email', authenticateToken, async (req, res) => {
  try {
    const { userId, startDate, endDate, email } = req.body;
    
    if (!req.user.isGestor && req.user.id != userId) {
      return res.status(403).json({ success: false, message: 'Acesso não autorizado' });
    }
    
    const registros = await new Promise((resolve, reject) => {
      db.all(
        `SELECT tipo, timestamp FROM registros 
         WHERE usuarioId = ? AND date(timestamp) BETWEEN date(?) AND date(?)
         ORDER BY timestamp`,
        [userId, startDate, endDate],
        (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        }
      );
    });
    
    const usuario = await new Promise((resolve, reject) => {
      db.get(
        "SELECT nome, setor FROM usuarios WHERE id = ?",
        [userId],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });
    
    let totalHoras = 0;
    let horasExtras = 0;
    let entradaAtual = null;
    
    for (const registro of registros) {
      if (registro.tipo === 'entrada') {
        entradaAtual = new Date(registro.timestamp).getTime();
      } else if (entradaAtual) {
        const horasDia = (new Date(registro.timestamp).getTime() - entradaAtual);
        totalHoras += horasDia;
        
        const jornadaDiaria = 8 * 60 * 60 * 1000;
        if (horasDia > jornadaDiaria) {
          horasExtras += (horasDia - jornadaDiaria);
        }
        
        entradaAtual = null;
      }
    }
    
    const formatHours = (ms) => {
      const horas = Math.floor(ms / (1000 * 60 * 60));
      const minutos = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
      return `${String(horas).padStart(2, '0')}:${String(minutos).padStart(2, '0')}`;
    };
    
    const html = `
      <h1>Espelho de Ponto</h1>
      <p><strong>Colaborador:</strong> ${usuario.nome}</p>
      <p><strong>Setor:</strong> ${usuario.setor}</p>
      <p><strong>Período:</strong> ${new Date(startDate).toLocaleDateString('pt-BR')} a ${new Date(endDate).toLocaleDateString('pt-BR')}</p>
      
      <h2>Registros</h2>
      <table border="1" cellpadding="5" cellspacing="0">
        <tr>
          <th>Data</th>
          <th>Horário</th>
          <th>Tipo</th>
        </tr>
        ${registros.map(r => `
          <tr>
            <td>${new Date(r.timestamp).toLocaleDateString('pt-BR')}</td>
            <td>${new Date(r.timestamp).toLocaleTimeString('pt-BR')}</td>
            <td>${r.tipo === 'entrada' ? 'Entrada' : r.tipo === 'saida' ? 'Saída' : 'Intervalo'}</td>
          </tr>
        `).join('')}
      </table>
      
      <h2>Totais</h2>
      <p><strong>Horas Trabalhadas:</strong> ${formatHours(totalHoras)}</p>
      <p><strong>Horas Extras:</strong> ${formatHours(horasExtras)}</p>
    `;
    
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: `Espelho de Ponto - ${usuario.nome}`,
      html: html
    };
    
    //await transporter.sendMail(mailOptions);
    
    res.json({ 
      success: true,
      message: 'Espelho de ponto enviado com sucesso',
      totalHoras: formatHours(totalHoras),
      horasExtras: formatHours(horasExtras)
    });
  } catch (error) {
    console.error('Erro ao enviar espelho de ponto:', error);
    res.status(500).json({ success: false, message: 'Erro ao enviar espelho de ponto' });
  }
});

// Rotas de configuração
app.get('/api/config/jornada', authenticateToken, async (req, res) => {
  try {
    const config = await new Promise((resolve, reject) => {
      db.get("SELECT * FROM config LIMIT 1", (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    res.json({ success: true, config });
  } catch (error) {
    console.error('Erro ao buscar configurações:', error);
    res.status(500).json({ success: false, message: 'Erro ao buscar configurações' });
  }
});

app.post('/api/config/jornada', authenticateToken, async (req, res) => {
  if (!req.user.isGestor) {
    return res.status(403).json({ success: false, message: 'Apenas gestores podem alterar configurações' });
  }

  const { horasDiarias, intervaloMinimo, toleranciaAtraso, horaExtraMinima } = req.body;

  try {
    await new Promise((resolve, reject) => {
      db.run(
        `UPDATE config SET 
          horasDiarias = ?,
          intervaloMinimo = ?,
          toleranciaAtraso = ?,
          horaExtraMinima = ?`,
        [horasDiarias, intervaloMinimo, toleranciaAtraso, horaExtraMinima],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });

    res.json({ 
      success: true,
      message: 'Configurações atualizadas com sucesso'
    });
  } catch (error) {
    console.error('Erro ao atualizar configurações:', error);
    res.status(500).json({ success: false, message: 'Erro ao atualizar configurações' });
  }
});

// Rotas de justificativas
app.get('/api/justificativas', authenticateToken, async (req, res) => {
  try {
    let justificativas;
    
    if (req.user.isGestor) {
      justificativas = await new Promise((resolve, reject) => {
        db.all(
          `SELECT j.*, u.nome as colaboradorNome 
           FROM justificativas j
           JOIN usuarios u ON j.usuarioId = u.id
           WHERE u.emailGestor = ?
           ORDER BY j.data DESC, j.horario DESC`,
          [req.user.email],
          (err, rows) => {
            if (err) reject(err);
            resolve(rows);
          }
        );
      });
    } else {
      justificativas = await new Promise((resolve, reject) => {
        db.all(
          "SELECT * FROM justificativas WHERE usuarioId = ? ORDER BY data DESC, horario DESC",
          [req.user.id],
          (err, rows) => {
            if (err) reject(err);
            resolve(rows);
          }
        );
      });
    }

    res.json({ success: true, justificativas });
  } catch (error) {
    console.error('Erro ao buscar justificativas:', error);
    res.status(500).json({ success: false, message: 'Erro ao buscar justificativas' });
  }
});

app.post('/api/justificativas/:id/aprovar', authenticateToken, async (req, res) => {
  if (!req.user.isGestor) {
    return res.status(403).json({ success: false, message: 'Apenas gestores podem aprovar justificativas' });
  }

  try {
    const justificativa = await new Promise((resolve, reject) => {
      db.get(
        "SELECT * FROM justificativas WHERE id = ?",
        [req.params.id],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });

    if (!justificativa) {
      return res.status(404).json({ success: false, message: 'Justificativa não encontrada' });
    }

    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE justificativas SET status = 'aprovado' WHERE id = ?",
        [req.params.id],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });

    const timestamp = new Date(`${justificativa.data}T${justificativa.horario}`).toISOString();
    
    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO registros (usuarioId, tipo, timestamp, justificado, motivoJustificativa) VALUES (?, ?, ?, ?, ?)",
        [justificativa.usuarioId, justificativa.tipo, timestamp, 1, justificativa.motivo],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });

    res.json({ 
      success: true,
      message: 'Justificativa aprovada e ponto registrado com sucesso'
    });
  } catch (error) {
    console.error('Erro ao aprovar justificativa:', error);
    res.status(500).json({ success: false, message: 'Erro ao aprovar justificativa' });
  }
});

app.post('/api/justificativas/:id/rejeitar', authenticateToken, async (req, res) => {
  if (!req.user.isGestor) {
    return res.status(403).json({ success: false, message: 'Apenas gestores podem rejeitar justificativas' });
  }

  try {
    const { motivoRejeicao } = req.body;
    
    if (!motivoRejeicao) {
      return res.status(400).json({ success: false, message: 'Motivo da rejeição é obrigatório' });
    }

    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE justificativas SET status = 'rejeitado', motivoRejeicao = ? WHERE id = ?",
        [motivoRejeicao, req.params.id],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });

    res.json({ 
      success: true,
      message: 'Justificativa rejeitada com sucesso'
    });
  } catch (error) {
    console.error('Erro ao rejeitar justificativa:', error);
    res.status(500).json({ success: false, message: 'Erro ao rejeitar justificativa' });
  }
});

// Função auxiliar para calcular distância
function calcularDistancia(lat1, lon1, lat2, lon2) {
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

// Rota padrão para o frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});