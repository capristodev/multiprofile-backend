const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração do Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('❌ Variáveis de ambiente do Supabase não configuradas!');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100 // máximo 100 requests por IP
});
app.use(limiter);

// Middleware de autenticação
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso necessário' });
  }

  try {
    const { data: session, error } = await supabaseAdmin
      .from('user_sessions')
      .select('*, users(*)')
      .eq('session_token', token)
      .eq('is_active', true)
      .single();

    if (error || !session) {
      return res.status(403).json({ error: 'Token inválido ou expirado' });
    }

    req.user = session.users;
    req.session = session;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Token inválido' });
  }
};

// Rotas
app.get('/', (req, res) => {
  res.json({ 
    message: 'MultiProfile Backend API',
    version: '1.0.0',
    status: 'online'
  });
});

// Rota de login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, device_id } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    // Buscar usuário
    const { data: user, error: userError } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (userError || !user) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Verificar senha
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Gerar token de sessão
    const sessionToken = uuidv4();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 dias

    // Criar sessão
    const { data: session, error: sessionError } = await supabaseAdmin
      .from('user_sessions')
      .insert({
        user_id: user.id,
        session_token: sessionToken,
        device_id: device_id || null,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        expires_at: expiresAt.toISOString(),
        is_active: true
      })
      .select()
      .single();

    if (sessionError) {
      return res.status(500).json({ error: 'Erro ao criar sessão' });
    }

    res.json({
      success: true,
      token: sessionToken,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        subscription_type: user.subscription_type
      }
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para obter serviços do usuário
app.get('/api/services', authenticateToken, async (req, res) => {
  try {
    const { data: services, error } = await supabaseAdmin
      .from('user_services')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('is_active', true)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ error: 'Erro ao buscar serviços' });
    }

    res.json({
      success: true,
      services: services || []
    });

  } catch (error) {
    console.error('Erro ao buscar serviços:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para obter versão da extensão
app.get('/api/version', async (req, res) => {
  try {
    const { data: version, error } = await supabaseAdmin
      .from('extension_versions')
      .select('*')
      .eq('is_latest', true)
      .single();

    if (error) {
      return res.status(500).json({ error: 'Erro ao buscar versão' });
    }

    res.json({
      success: true,
      version: version
    });

  } catch (error) {
    console.error('Erro ao buscar versão:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota de health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Middleware de erro
app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err);
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
  console.log(`📡 Supabase conectado: ${supabaseUrl}`);
});

module.exports = app;
