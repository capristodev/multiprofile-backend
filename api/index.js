const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.json({ 
    message: 'MultiProfile Backend API',
    version: '1.0.0',
    status: 'online'
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

module.exports = app;
