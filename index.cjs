const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const http = require('http');
const socketIo = require('socket.io');
const router = express.Router();
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
app.use(express.json());
const server = http.createServer(app);

const io = socketIo(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"]
  }
});

// --- Middleware sécurité ---
app.use(helmet());
app.use(morgan('combined'));
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// --- Rate limiter ---
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requêtes par IP
});
app.use('/api/', limiter);

// --- Supabase ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// --- Secret JWT ---
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-prod';

// --- Middleware d’authentification ---
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  console.log('Token reçu:', token);
  if (!token) return res.status(401).json({ error: 'Token d’accès requis' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Payload décodée:', decoded);

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', decoded.userId)
      .single();

    if (error || !user) {
      console.log('Utilisateur non trouvé ou erreur:', error);
      return res.status(401).json({ error: 'Utilisateur introuvable' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.log('Erreur jwt:', err);
    return res.status(403).json({ error: 'Token invalide ou expiré' });
  }
};



// --- Routes d’authentification ---

// Enregistrement
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Tous les champs sont requis' });

    if (password.length < 6)
      return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères' });

    const { data: existingUser, error: existingError } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();

    if (existingUser) return res.status(400).json({ error: 'Cet email est déjà utilisé' });
    if (existingError && existingError.code !== 'PGRST116') { // PGRST116 = no rows found, okay here
      console.error('Erreur vérification user existant:', existingError);
      return res.status(500).json({ error: 'Erreur serveur' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        id: uuidv4(),
        name,
        email,
        password: hashedPassword,
        plan: 'free',
        credits: 20,
        max_credits: 20,
        is_banned: false,
        is_admin: false,
        created_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) {
      console.error('Erreur création utilisateur:', error);
      return res.status(500).json({ error: 'Erreur lors de la création du compte' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

    const { password: _, ...userWithoutPassword } = user;

    res.status(201).json({
      success: true,
      user: {
        ...userWithoutPassword,
        isAdmin: user.is_admin,
        isBanned: user.is_banned,
        maxCredits: user.max_credits,
        createdAt: user.created_at
      },
      token
    });
  } catch (error) {
    console.error('Erreur register:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Connexion
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) return res.status(401).json({ error: 'Email ou mot de passe invalide' });
    if (user.is_banned) return res.status(403).json({ error: 'Compte banni' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Email ou mot de passe invalide' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    const { password: _, ...userWithoutPassword } = user;

    res.json({
      success: true,
      user: {
        ...userWithoutPassword,
        isAdmin: user.is_admin,
        isBanned: user.is_banned,
        maxCredits: user.max_credits,
        createdAt: user.created_at
      },
      token
    });
  } catch (error) {
    console.error('Erreur login:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Récupérer les infos du user connecté
app.get('/api/me', authenticateToken, (req, res) => {
  const { password: _, ...userWithoutPassword } = req.user;
  res.json({
    success: true,
    user: {
      ...userWithoutPassword,
      isAdmin: req.user.is_admin,
      isBanned: req.user.is_banned,
      maxCredits: req.user.max_credits,
      createdAt: req.user.created_at
    }
  });
});

// --- Admin routes ---
// Liste des utilisateurs
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: "Accès refusé : admin seulement" });
  }

  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, name, email, plan, is_admin, is_banned, created_at, credits')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Erreur récupération utilisateurs:', error);
      return res.status(500).json({ error: 'Erreur serveur' });
    }

    res.json({ success: true, users });
  } catch (err) {
    console.error('Erreur serveur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Modifier un utilisateur
app.put('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: "Accès refusé : admin seulement" });
  }

  const userIdToUpdate = req.params.id;
  const { plan, is_admin, is_banned } = req.body;

  if (!plan && is_admin === undefined && is_banned === undefined) {
    return res.status(400).json({ error: "Aucune donnée valide à modifier" });
  }

  try {
    const updates = {};
    if (plan) updates.plan = plan;
    if (is_admin !== undefined) updates.is_admin = is_admin;
    if (is_banned !== undefined) updates.is_banned = is_banned;

    const { data, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', userIdToUpdate)
      .select()
      .single();

    if (error) {
      console.error('Erreur mise à jour utilisateur:', error);
      return res.status(500).json({ error: 'Erreur lors de la mise à jour' });
    }

    res.json({ success: true, user: data });
  } catch (err) {
    console.error('Erreur serveur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// --- Route récupération des messages ---
app.get('/api/chat/messages', authenticateToken, async (req, res) => {
  try {
    const { data: messages, error } = await supabase
      .from('chat_messages')
      .select(`
        id,
        message,
        created_at,
        user_id,
        users (
          id,
          name,
          is_admin
        )
      `)
      .order('created_at', { ascending: true })
      .limit(100);

    if (error) {
      console.error('Erreur récupération messages:', error);
      return res.status(500).json({ error: 'Erreur lors de la récupération des messages' });
    }

    const formattedMessages = messages.map(msg => ({
      id: msg.id,
      text: msg.message,
      userId: msg.user_id,
      userName: msg.users?.name || 'Anonyme',
      timestamp: new Date(msg.created_at),
      isAdmin: msg.users?.is_admin || false
    }));

    res.json({ success: true, messages: formattedMessages });
  } catch (error) {
    console.error('Erreur récupération messages:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// --- Routes historique des recherches ---
// Récupérer l'historique des recherches
app.get('/api/search-history', authenticateToken, async (req, res) => {
  try {
    const { data: history, error } = await supabase
      .from('search_history')
      .select('id, query, results_count, created_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(10);

    if (error) {
      console.error('Erreur récupération historique:', error);
      return res.status(500).json({ error: 'Erreur lors de la récupération de l\'historique' });
    }

    res.json({ success: true, history });
  } catch (error) {
    console.error('Erreur historique:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Ajouter une recherche à l'historique
app.post('/api/search-history', authenticateToken, async (req, res) => {
  try {
    const { query, results_count } = req.body;
    if (!query) {
      return res.status(400).json({ error: 'Query requis' });
    }

    // Ajouter la nouvelle recherche
    const { error: insertError } = await supabase
      .from('search_history')
      .insert([{
        user_id: req.user.id,
        query,
        results_count: results_count || 0
      }]);

    if (insertError) {
      console.error('Erreur ajout historique:', insertError);
      return res.status(500).json({ error: 'Erreur lors de l\'ajout à l\'historique' });
    }

    // Garder seulement les 10 dernières recherches
    const { data: allHistory, error: selectError } = await supabase
      .from('search_history')
      .select('id')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (!selectError && allHistory && allHistory.length > 10) {
      const toDelete = allHistory.slice(10).map(item => item.id);
      await supabase
        .from('search_history')
        .delete()
        .in('id', toDelete);
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Erreur ajout historique:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// --- Route pour valider une clé d'accès ---
app.post('/api/redeem', async (req, res) => {
  const { email, key } = req.body;
  if (!email || !key) {
    return res.status(400).json({ error: "Email et clé requis" });
  }

  try {
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: "Utilisateur introuvable" });
    }

    const { data: redeemKey, error: keyError } = await supabase
      .from('redeem_keys')
      .select('*')
      .eq('key', key)
      .eq('used', false)
      .single();

    if (keyError || !redeemKey) {
      return res.status(400).json({ error: "Clé invalide ou déjà utilisée" });
    }

    const { data: updatedUser, error: updateError } = await supabase
      .from('users')
      .update({ plan: redeemKey.plan })
      .eq('id', user.id)
      .select()
      .single();

    if (updateError) {
      console.error("Erreur mise à jour plan :", updateError);
      return res.status(500).json({ error: "Erreur lors de la mise à jour du plan" });
    }

    const { error: markUsedError } = await supabase
      .from('redeem_keys')
      .update({ used: true })
      .eq('key', redeemKey.key);  // <-- Ici on utilise 'key' au lieu de 'id'

    if (markUsedError) {
      console.error("Erreur mise à jour clé :", markUsedError);
      return res.status(500).json({ error: "Erreur lors de la mise à jour de la clé : " + markUsedError.message });
    }

    res.json({
      success: true,
      plan: updatedUser.plan
    });

  } catch (err) {
    console.error("Erreur /api/redeem:", err);
    console.log("📩 BODY reçu :", req.body);
    res.status(500).json({ error: "Erreur serveur" });
  }
});


// Ajouter des crédits à un utilisateur via email (admin seulement)
app.post('/api/admin/add-credits', authenticateToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: "Accès refusé : admin seulement" });
  }

  const { email, amount } = req.body;
  if (!email || typeof amount !== "number" || amount <= 0) {
    return res.status(400).json({ error: "Email et montant valide requis" });
  }

  try {
    // Récupérer l'utilisateur par email
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: "Utilisateur introuvable" });
    }

    const currentCredits = Number(user.credits) || 0;
    const newCredits = currentCredits + amount;

    // Mettre à jour les crédits
    const { data: updatedUser, error: updateError } = await supabase
      .from('users')
      .update({ credits: newCredits })
      .eq('id', user.id)
      .select()
      .single();

    if (updateError) {
      console.error('Erreur ajout crédits:', updateError);
      return res.status(500).json({ error: 'Erreur serveur' });
    }

    res.json({
      success: true,
      message: `${amount} crédits ajoutés à ${email}`,
      credits: updatedUser.credits
    });
  } catch (err) {
    console.error('Erreur /api/admin/add-credits:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// --- AJOUT : Route décrémentation crédits ---
app.post('/api/use-credit', async (req, res) => {
  // Ici, pour test, on récupère l'utilisateur d'une façon simple, genre un userId en body
  const { userId } = req.body;

  if (!userId) return res.status(400).json({ error: 'userId requis' });

  const { data: user, error: errUser } = await supabase.from('users').select('*').eq('id', userId).single();

  if (errUser || !user) return res.status(404).json({ error: 'Utilisateur non trouvé' });

  if (user.credits <= 0) return res.status(400).json({ error: 'Pas assez de crédits' });

  const { data, error } = await supabase
    .from('users')
    .update({ credits: user.credits - 1 })
    .eq('id', userId);

  if (error) {
    console.error('Erreur décrémentation crédits:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }

  res.json({ success: true, creditsLeft: user.credits - 1 });
});

const https = require('https');

// --- Route recherche avec plan utilisateur ---
app.post('/api/search', authenticateToken, async (req, res) => {
  console.log('--- Nouvelle recherche reçue ---');
  console.log('Utilisateur:', req.user);
  console.log('Corps de la requête:', req.body);

  const { query, limit = 100, lang = 'fr' } = req.body;

  if (!query || typeof query !== 'string') {
    console.log('Recherche échouée : paramètre query manquant ou invalide');
    return res.status(400).json({ error: 'Paramètre query requis' });
  }

  try {
    // Vérification crédits utilisateur
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('credits, plan, search_count')
      .eq('id', req.user.id)
      .single();

    if (userError) {
      console.error('Erreur lecture user credits:', userError);
      return res.status(500).json({ error: 'Erreur interne.' });
    }

    if (!userData || userData.credits <= 0) {
      return res.status(403).json({ success: false, error: 'Crédits insuffisants.' });
    }

    const userPlan = req.user.plan || (userData.plan || 'free');
    console.log('Plan utilisateur:', userPlan);

    const allowedPlans = ['standard', 'advanced', 'pro', 'premium'];

    if (!allowedPlans.includes(userPlan)) {
      console.log('Plan non autorisé pour la recherche:', userPlan);
      return res.json({
        success: false,
        data: null,
        error: 'Vous devez avoir un abonnement valide pour effectuer des recherches.',
        accessDenied: true,
        plan: userPlan,
      });
    }

    console.log("Appel à l'API externe LeakOSINT avec la requête:", query);

    const API_URL = 'https://leakosintapi.com/';
    const TOKEN = '8210577188:Rkm4TrsU';

    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: TOKEN,
        request: query,
        limit,
        lang,
      }),
    });

    console.log('Réponse API externe status:', response.status);

    const apiData = await response.json();

    if (!response.ok) {
      console.log('Erreur lors de la recherche externe:', apiData);
      return res.status(response.status).json({
        success: false,
        error: 'Erreur lors de la recherche externe',
      });
    }

    // Transformation de la structure : apiData.data est un objet avec plusieurs sources
    const results = Object.entries(apiData.data || {}).map(([name, value]) => ({
      name,
      infoLeak: value.InfoLeak,
      numOfResults: value.NumOfResults,
      data: value.Data || [],
    }));

    console.log('Nombre de sources reçues:', results.length);

    // Décrémente les crédits utilisateur et incrémente search_count
    const newSearchCount = (typeof userData.search_count === 'number' ? userData.search_count : 0) + 1;

    const { error: updateError } = await supabase
      .from('users')
      .update({ 
        credits: userData.credits - 1,
        search_count: newSearchCount
      })
      .eq('id', req.user.id);

    if (updateError) {
      console.error('Erreur mise à jour crédits ou search_count:', updateError);
      // On continue quand même
    } else {
      console.log(`Crédits et search_count mis à jour : credits=${userData.credits - 1}, search_count=${newSearchCount}`);
    }

    // Ajout dans l'historique
    try {
      await supabase.from('search_history').insert([
        {
          user_id: req.user.id,
          query,
          results_count: results.reduce((sum, r) => sum + (r.numOfResults || 0), 0),
        },
      ]);
      console.log('Historique mis à jour');

      // Garde les 10 dernières recherches
      const { data: allHistory } = await supabase
        .from('search_history')
        .select('id')
        .eq('user_id', req.user.id)
        .order('created_at', { ascending: false });

      if (allHistory && allHistory.length > 10) {
        const toDelete = allHistory.slice(10).map((item) => item.id);
        await supabase.from('search_history').delete().in('id', toDelete);
        console.log('Anciennes recherches supprimées:', toDelete.length);
      }
    } catch (historyError) {
      console.error('Erreur ajout historique:', historyError);
    }

    res.json({
      success: true,
      data: results,
      plan: userPlan,
    });
  } catch (err) {
    console.error('Erreur serveur recherche:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// --- Route lookup Discord ---
app.post('/api/discordlookup', authenticateToken, async (req, res) => {
  const { discordId } = req.body;

  if (!discordId || typeof discordId !== 'string' || discordId.trim() === '') {
    return res.status(400).json({ success: false, error: 'Discord ID invalide.' });
  }

  try {
    // Vérifie crédits utilisateur avant requête
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('credits, search_count')
      .eq('id', req.user.id)
      .single();

    if (userError) {
      console.error('Erreur lecture user credits:', userError);
      return res.status(500).json({ success: false, error: 'Erreur interne.' });
    }

    if (!userData || userData.credits <= 0) {
      return res.status(403).json({ success: false, error: 'Crédits insuffisants.' });
    }

    const url = `https://discordlookup.mesalytic.moe/v1/user/${encodeURIComponent(discordId.trim())}`;

    https.get(url, async (response) => {
      let data = '';

      response.on('data', chunk => {
        data += chunk;
      });

      response.on('end', async () => {
        if (response.statusCode !== 200) {
          return res.status(response.statusCode).json({ success: false, error: 'Erreur lors de la récupération des données Discord.' });
        }

        try {
          const jsonData = JSON.parse(data);

          // Décrémente les crédits utilisateur et incrémente search_count
          const newSearchCount = (typeof userData.search_count === 'number' ? userData.search_count : 0) + 1;

          const { error: updateError } = await supabase
            .from('users')
            .update({ 
              credits: userData.credits - 1,
              search_count: newSearchCount
            })
            .eq('id', req.user.id);

          if (updateError) {
            console.error('Erreur mise à jour crédits ou search_count:', updateError);
            // Continue quand même
          } else {
            console.log(`Crédits et search_count mis à jour : credits=${userData.credits - 1}, search_count=${newSearchCount}`);
          }

          // Enregistre la recherche dans search_history
          const { error: insertError } = await supabase
            .from('search_history')
            .insert({
              user_id: req.user.id,
              query: discordId.trim(),
              results_count: jsonData ? 1 : 0,
              created_at: new Date().toISOString()
            });

          if (insertError) {
            console.error('Erreur insertion historique:', insertError);
            // Continue quand même
          } else {
            // Garder seulement les 10 dernières recherches
            const { data: allHistory, error: selectError } = await supabase
              .from('search_history')
              .select('id')
              .eq('user_id', req.user.id)
              .order('created_at', { ascending: false });

            if (!selectError && allHistory && allHistory.length > 10) {
              const toDelete = allHistory.slice(10).map(item => item.id);
              await supabase
                .from('search_history')
                .delete()
                .in('id', toDelete);
            }
          }

          res.json({ success: true, data: jsonData });
        } catch (err) {
          res.status(500).json({ success: false, error: 'Erreur lors du parsing des données.' });
        }
      });
    }).on('error', (err) => {
      console.error('Erreur DiscordLookup:', err);
      res.status(500).json({ success: false, error: 'Erreur serveur.' });
    });

  } catch (err) {
    console.error('Erreur serveur DiscordLookup:', err);
    res.status(500).json({ success: false, error: 'Erreur serveur.' });
  }
});





let onlineUsersCount = 0;

io.on('connection', (socket) => {
  onlineUsersCount++;
  console.log('Un utilisateur connecté', socket.id, '-> total:', onlineUsersCount);

  // Diffuser le nouveau nombre d’utilisateurs à tous
  io.emit('online_users_count', onlineUsersCount);

  socket.on('send_message', async (data) => {
    console.log('Reçu send_message:', data);

    if (!data?.token || !data?.message) {
      console.log('Missing token or message');
      return;
    }

    try {
      const decoded = jwt.verify(data.token, process.env.JWT_SECRET);
      console.log('Token décodé:', decoded);

      const userId = decoded.userId;

      const { data: insertedData, error } = await supabase
        .from('chat_messages')
        .insert([{ user_id: userId, message: data.message, created_at: new Date().toISOString() }])
        .select()
        .single();

      if (error) {
        console.error('Erreur insertion message:', error);
        socket.emit('message_error', { error: error.message });
        return;
      }

      console.log('Message inséré:', insertedData);

      // Émettre à tous sauf à l’émetteur
      socket.broadcast.emit('new_message', {
        id: insertedData.id,
        userId: insertedData.user_id,
        text: insertedData.message,
        timestamp: insertedData.created_at,
      });
    } catch (err) {
      console.error('Erreur token ou insertion:', err);
      socket.emit('message_error', { error: err.message });
    }
  });

  socket.on('disconnect', () => {
    onlineUsersCount--;
    console.log('Utilisateur déconnecté', socket.id, '-> total:', onlineUsersCount);
    io.emit('online_users_count', onlineUsersCount);
  });
});



// --- Lancement du serveur ---
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});
