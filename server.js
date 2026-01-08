// server.js - Complete Medical System Backend
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const http = require('http');
const axios = require('axios');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
// CORS Configuration for Production
const allowedOrigins = [
  'https://medical-system0.netlify.app',
  'http://localhost:5500',
  'http://localhost:3000',
  'http://127.0.0.1:5500'
];

const corsOptions = {
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy violation'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

const io = new Server(server, { 
  cors: { 
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  } 
});

app.use(cors(corsOptions));
app.use(express.json());
app.use((req, res, next) => { console.log(`${req.method} ${req.path}`); next(); });

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/medical_health_system';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// SCHEMAS
const userSchema = new mongoose.Schema({
  userId: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  dateOfBirth: { type: Date, required: true },
  bloodGroup: { type: String, required: true },
  emergencyContact: { type: String, required: true },
  address: { type: String, required: true },
  registeredBy: { type: String, default: 'self' },
  createdAt: { type: Date, default: Date.now }
});

const hospitalSchema = new mongoose.Schema({
  hospitalId: { type: String, unique: true, required: true },
  hospitalName: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const hospitalVisitSchema = new mongoose.Schema({
  visitId: { type: String, unique: true, required: true },
  userId: { type: String, required: true },
  hospitalId: { type: String, required: true },
  hospitalName: { type: String, required: true },
  visitDate: { type: Date, default: Date.now },
  diagnosis: { type: String, required: true },
  prescription: { type: String, required: true },
  labResults: String,
  doctorName: { type: String, required: true },
  notes: String
});

const bloodBankSchema = new mongoose.Schema({
  hospitalId: { type: String, required: true },
  bloodType: { type: String, required: true },
  availableUnits: { type: Number, required: true },
  lastUpdated: { type: Date, default: Date.now }
});

const criticalStockAlertSchema = new mongoose.Schema({
  alertId: { type: String, unique: true, required: true },
  hospitalId: { type: String, required: true },
  hospitalName: { type: String, required: true },
  bloodType: { type: String, required: true },
  currentUnits: { type: Number, required: true },
  threshold: { type: Number, default: 10 },
  status: { type: String, default: 'active' },
  createdAt: { type: Date, default: Date.now },
  acknowledgedBy: [{ hospitalId: String, hospitalName: String, response: String, timestamp: Date }]
});

const emergencyAlertSchema = new mongoose.Schema({
  alertId: { type: String, unique: true, required: true },
  hospitalId: { type: String, required: true },
  hospitalName: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, default: 'general' },
  priority: { type: String, default: 'medium' },
  status: { type: String, default: 'active' },
  createdAt: { type: Date, default: Date.now },
  acknowledgedBy: [{ hospitalId: String, hospitalName: String, response: String, timestamp: Date }]
});

const User = mongoose.model('User', userSchema);
const Hospital = mongoose.model('Hospital', hospitalSchema);
const HospitalVisit = mongoose.model('HospitalVisit', hospitalVisitSchema);
const BloodBank = mongoose.model('BloodBank', bloodBankSchema);
const CriticalStockAlert = mongoose.model('CriticalStockAlert', criticalStockAlertSchema);
const EmergencyAlert = mongoose.model('EmergencyAlert', emergencyAlertSchema);

function generateUniqueId(prefix) {
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
}

const JWT_SECRET = process.env.JWT_SECRET || 'medical_health_super_secret_key_2024';
const BLOOD_THRESHOLD = parseInt(process.env.BLOOD_THRESHOLD) || 10;
const GOOGLE_AI_API_KEY = process.env.GOOGLE_AI_API_KEY || '';

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// AUTHENTICATION
app.post('/api/register/patient', async (req, res) => {
  try {
    const { name, email, password, dateOfBirth, bloodGroup, emergencyContact, address, registeredBy } = req.body;
    if (!name || !email || !dateOfBirth || !bloodGroup || !emergencyContact || !address) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ success: false, message: 'Email exists' });
    
    const hashedPassword = bcrypt.hashSync(password || 'temp123', 10);

    const userId = generateUniqueId('PAT');
    await new User({ userId, name, email, password: hashedPassword, dateOfBirth, bloodGroup, emergencyContact, address, registeredBy: registeredBy || 'self' }).save();
    res.status(201).json({ success: true, userId, name });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/register/hospital', async (req, res) => {
  try {
    const { hospitalName, email, password } = req.body;
    if (!hospitalName || !email || !password) return res.status(400).json({ success: false, message: 'All fields required' });
    const existing = await Hospital.findOne({ email });
    if (existing) return res.status(400).json({ success: false, message: 'Email exists' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const hospitalId = generateUniqueId('HOSP');
    await new Hospital({ hospitalId, hospitalName, email, password: hashedPassword }).save();
    res.status(201).json({ success: true, hospitalId, hospitalName });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/login/patient', async (req, res) => {
  try {
    const { name, email, userId } = req.body;
    const user = await User.findOne({ email, userId, name });
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    
    const token = jwt.sign({ userId: user.userId, email: user.email, role: 'patient' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, user: { userId: user.userId, name: user.name, email: user.email, bloodGroup: user.bloodGroup, dateOfBirth: user.dateOfBirth, emergencyContact: user.emergencyContact, address: user.address } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/login/hospital', async (req, res) => {
  try {
    const { hospitalName, email, hospitalId } = req.body;
    const hospital = await Hospital.findOne({ email, hospitalId, hospitalName });
    if (!hospital) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    
    const token = jwt.sign({ hospitalId: hospital.hospitalId, email: hospital.email, role: 'hospital' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, hospital: { hospitalId: hospital.hospitalId, hospitalName: hospital.hospitalName, email: hospital.email } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// PATIENT ROUTES
app.get('/api/user/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.params.id }).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/visits/:userId', authenticateToken, async (req, res) => {
  try {
    const visits = await HospitalVisit.find({ userId: req.params.userId }).sort({ visitDate: -1 });
    res.json({ success: true, visits });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// HOSPITAL ROUTES
app.post('/api/addVisit', authenticateToken, async (req, res) => {
  try {
    const { userId, hospitalId, hospitalName, diagnosis, prescription, labResults, doctorName, notes } = req.body;
    if (!userId || !hospitalId || !diagnosis || !prescription || !doctorName) {
      return res.status(400).json({ success: false, message: 'Required fields missing' });
    }
    const patient = await User.findOne({ userId });
    if (!patient) return res.status(404).json({ success: false, message: 'Patient not found' });
    
    const visitId = generateUniqueId('VISIT');
    await new HospitalVisit({ visitId, userId, hospitalId, hospitalName, diagnosis, prescription, labResults, doctorName, notes }).save();
    res.status(201).json({ success: true, message: 'Visit added' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/patient/search/:userId', authenticateToken, async (req, res) => {
  try {
    const patient = await User.findOne({ userId: req.params.userId }).select('-password');
    if (!patient) return res.status(404).json({ success: false, message: 'Patient not found' });
    const visits = await HospitalVisit.find({ userId: req.params.userId }).sort({ visitDate: -1 });
    res.json({ success: true, patient, visits });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// BLOOD BANK
app.get('/api/blood/:hospitalId', authenticateToken, async (req, res) => {
  try {
    const bloodData = await BloodBank.find({ hospitalId: req.params.hospitalId });
    res.json({ success: true, bloodData });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/blood/add', authenticateToken, async (req, res) => {
  try {
    const { hospitalId, hospitalName, bloodType, units } = req.body;
    let blood = await BloodBank.findOne({ hospitalId, bloodType });
    if (blood) {
      blood.availableUnits += units;
      blood.lastUpdated = Date.now();
      await blood.save();
    } else {
      blood = await new BloodBank({ hospitalId, bloodType, availableUnits: units }).save();
    }
    if (blood.availableUnits >= BLOOD_THRESHOLD) {
      await CriticalStockAlert.updateMany({ hospitalId, bloodType, status: 'active' }, { status: 'resolved' });
    }
    res.json({ success: true, bloodRecord: blood });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/blood/remove', authenticateToken, async (req, res) => {
  try {
    const { hospitalId, hospitalName, bloodType, units } = req.body;
    let blood = await BloodBank.findOne({ hospitalId, bloodType });
    if (!blood || blood.availableUnits < units) {
      return res.status(400).json({ success: false, message: 'Insufficient units' });
    }
    blood.availableUnits -= units;
    blood.lastUpdated = Date.now();
    await blood.save();
    
    if (blood.availableUnits < BLOOD_THRESHOLD) {
      const existing = await CriticalStockAlert.findOne({ hospitalId, bloodType, status: 'active' });
      if (!existing) {
        const alertId = generateUniqueId('ALERT');
        await new CriticalStockAlert({ alertId, hospitalId, hospitalName, bloodType, currentUnits: blood.availableUnits, threshold: BLOOD_THRESHOLD }).save();
        io.emit('criticalStock', { alertId, hospitalId, hospitalName, bloodType, currentUnits: blood.availableUnits });
      }
    }
    res.json({ success: true, bloodRecord: blood });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/blood/update', authenticateToken, async (req, res) => {
  try {
    const { hospitalId, hospitalName, bloodType, availableUnits } = req.body;
    let blood = await BloodBank.findOne({ hospitalId, bloodType });
    if (blood) {
      blood.availableUnits = availableUnits;
      blood.lastUpdated = Date.now();
      await blood.save();
    } else {
      blood = await new BloodBank({ hospitalId, bloodType, availableUnits }).save();
    }
    
    if (availableUnits < BLOOD_THRESHOLD) {
      const existing = await CriticalStockAlert.findOne({ hospitalId, bloodType, status: 'active' });
      if (!existing) {
        const alertId = generateUniqueId('ALERT');
        await new CriticalStockAlert({ alertId, hospitalId, hospitalName, bloodType, currentUnits: availableUnits, threshold: BLOOD_THRESHOLD }).save();
        io.emit('criticalStock', { alertId, hospitalId, hospitalName, bloodType, currentUnits: availableUnits });
      }
    } else {
      await CriticalStockAlert.updateMany({ hospitalId, bloodType, status: 'active' }, { status: 'resolved' });
    }
    res.json({ success: true, bloodRecord: blood });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// CRITICAL ALERTS
app.get('/api/alerts/critical', authenticateToken, async (req, res) => {
  try {
    const alerts = await CriticalStockAlert.find({ status: 'active' }).sort({ createdAt: -1 });
    res.json({ success: true, alerts });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/alerts/critical/acknowledge', authenticateToken, async (req, res) => {
  try {
    const { alertId, hospitalId, hospitalName, response } = req.body;
    const alert = await CriticalStockAlert.findOne({ alertId });
    if (!alert) return res.status(404).json({ success: false, message: 'Alert not found' });
    alert.acknowledgedBy.push({ hospitalId, hospitalName, response, timestamp: new Date() });
    await alert.save();
    res.json({ success: true, alert });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// EMERGENCY ALERTS
app.post('/api/alerts/emergency', authenticateToken, async (req, res) => {
  try {
    const { hospitalId, hospitalName, message, type, priority } = req.body;
    const alertId = generateUniqueId('EMRG');
    const alert = await new EmergencyAlert({ alertId, hospitalId, hospitalName, message, type: type || 'general', priority: priority || 'medium' }).save();
    io.emit('emergencyAlert', { alertId, hospitalName, message, type, priority, timestamp: new Date() });
    res.json({ success: true, alert });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/alerts/emergency', authenticateToken, async (req, res) => {
  try {
    const alerts = await EmergencyAlert.find({ status: 'active' }).sort({ createdAt: -1 });
    res.json({ success: true, alerts });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/alerts/emergency/acknowledge', authenticateToken, async (req, res) => {
  try {
    const { alertId, hospitalId, hospitalName, response } = req.body;
    const alert = await EmergencyAlert.findOne({ alertId });
    if (!alert) return res.status(404).json({ success: false, message: 'Alert not found' });
    alert.acknowledgedBy.push({ hospitalId, hospitalName, response, timestamp: new Date() });
    await alert.save();
    res.json({ success: true, alert });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// CHATBOT - COMPLETELY FIXED VERSION WITH FULL LOGGING
const chatCache = new Map();

// Function to log complete AI responses
function logAIResponse(response, cached = false, fallback = false) {
  console.log('\n' + '='.repeat(80));
  console.log(`🤖 AI Response ${cached ? '(CACHED)' : fallback ? '(FALLBACK)' : '(FRESH)'}:`);
  console.log('='.repeat(80));
  console.log(response);
  console.log(`Length: ${response.length} characters`);
  console.log('='.repeat(80) + '\n');
}

app.post('/api/chatbot', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;
    console.log('📨 Chatbot request received:', message);
    
    if (!message) {
      return res.status(400).json({ success: false, message: 'Message required' });
    }
    
    const cacheKey = message.toLowerCase().trim();
    if (chatCache.has(cacheKey)) {
      console.log('💾 Returning cached response');
      const cachedResponse = chatCache.get(cacheKey);
      logAIResponse(cachedResponse, true, false);
      return res.json({ success: true, response: cachedResponse, cached: true });
    }

    if (!GOOGLE_AI_API_KEY) {
      console.log('⚠️ No API key found, using fallback');
      const fallback = getFallbackResponse(message);
      logAIResponse(fallback, false, true);
      return res.json({ success: true, response: fallback, fallback: true });
    }

    console.log('🤖 Calling Google AI API...');
    
    // Correct Gemini API endpoint (v1beta)
    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GOOGLE_AI_API_KEY}`;
    
    const requestBody = {
      contents: [{
        parts: [{
          text: `You are a helpful medical health assistant. Provide clear, accurate health advice in 2-3 sentences. Be friendly and supportive.\n\nUser question: ${message}\n\nYour response:`
        }]
      }],
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 500, // Increased for longer responses
        topP: 0.8,
        topK: 40
      }
    };

    console.log('🔗 API URL:', apiUrl.substring(0, 100) + '...');
    
    const response = await axios.post(apiUrl, requestBody, {
      timeout: 20000,
      headers: {
        'Content-Type': 'application/json'
      },
      validateStatus: function (status) {
        return status < 500; // Resolve only if status < 500
      }
    });

    console.log('📡 API Response Status:', response.status);

    if (response.status !== 200) {
      console.error('❌ API Error:', response.status, response.data);
      const fallback = getFallbackResponse(message);
      logAIResponse(fallback, false, true);
      return res.json({ success: true, response: fallback, fallback: true, error: response.data });
    }

    const aiResponse = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
    
    if (!aiResponse) {
      console.error('❌ No response text in API response:', JSON.stringify(response.data));
      const fallback = getFallbackResponse(message);
      logAIResponse(fallback, false, true);
      return res.json({ success: true, response: fallback, fallback: true });
    }

    // Log the complete AI response
    logAIResponse(aiResponse, false, false);
    
    // Cache the response
    if (chatCache.size > 100) {
      const firstKey = chatCache.keys().next().value;
      chatCache.delete(firstKey);
    }
    chatCache.set(cacheKey, aiResponse);
    
    res.json({ success: true, response: aiResponse, cached: false });
    
  } catch (error) {
    console.error('❌ Chatbot Error Details:');
    console.error('Error Message:', error.message);
    console.error('Error Response:', error.response?.data);
    console.error('Error Status:', error.response?.status);
    
    const fallback = getFallbackResponse(req.body.message);
    logAIResponse(fallback, false, true);
    res.json({ 
      success: true, 
      response: fallback, 
      fallback: true,
      error: error.message,
      details: error.response?.data?.error?.message || 'Connection error'
    });
  }
});

function getFallbackResponse(message) {
  const msg = message.toLowerCase();
  
  // Diet & Nutrition
  if (msg.includes('diet') || msg.includes('food') || msg.includes('nutrition') || msg.includes('eat')) {
    return '🥗 **Healthy Diet Tips:** Eat 5 servings of colorful fruits and vegetables daily. Choose whole grains over refined grains. Include lean proteins like fish, chicken, and legumes. Stay hydrated with 8 glasses of water. Limit processed foods, added sugars, and excessive salt.';
  }
  
  // Exercise & Fitness
  if (msg.includes('exercise') || msg.includes('workout') || msg.includes('fitness') || msg.includes('physical')) {
    return '💪 **Exercise Guidelines:** Aim for 150 minutes of moderate aerobic activity weekly. Include strength training 2-3 times per week. Start slowly and gradually increase intensity. Walking, swimming, cycling are excellent choices. Always warm up before and cool down after exercise.';
  }
  
  // Diabetes
  if (msg.includes('diabetes') || msg.includes('sugar') || msg.includes('blood sugar')) {
    return '🩺 **Diabetes Management:** Monitor blood sugar levels regularly as prescribed. Follow a balanced diet with controlled carbohydrates. Exercise 30 minutes daily. Take medications exactly as directed. Avoid sugary drinks and maintain healthy weight. Schedule regular check-ups with your healthcare provider.';
  }
  
  // Blood Pressure
  if (msg.includes('pressure') || msg.includes('bp') || msg.includes('hypertension') || msg.includes('blood pressure')) {
    return '💓 **Blood Pressure Control:** Reduce sodium intake to less than 2,300mg daily. Exercise regularly (150 min/week). Maintain a healthy weight. Limit alcohol consumption. Manage stress through relaxation techniques. Monitor BP daily and keep a log. Avoid smoking.';
  }
  
  // Sleep
  if (msg.includes('sleep') || msg.includes('insomnia') || msg.includes('rest') || msg.includes('tired')) {
    return '😴 **Better Sleep Habits:** Maintain consistent sleep schedule (same bedtime/wake time). Aim for 7-9 hours nightly. Avoid screens 1 hour before bed. Keep bedroom cool (60-67°F), dark, and quiet. Avoid caffeine after 2 PM. Practice relaxation before sleep.';
  }
  
  // Stress & Mental Health
  if (msg.includes('stress') || msg.includes('anxiety') || msg.includes('mental') || msg.includes('worry') || msg.includes('depression')) {
    return '🧘 **Stress Management:** Practice deep breathing exercises (4-7-8 technique). Try meditation or mindfulness 10 minutes daily. Regular physical activity reduces stress hormones. Maintain social connections. Get adequate sleep (7-9 hours). Consider professional counseling if stress is overwhelming.';
  }
  
  // Weight Management
  if (msg.includes('weight') || msg.includes('lose') || msg.includes('obesity') || msg.includes('fat') || msg.includes('overweight')) {
    return '⚖️ **Healthy Weight Management:** Set realistic goals (1-2 pounds per week). Balance diet with portion control. Combine cardio and strength training. Track food intake using a journal or app. Stay hydrated throughout the day. Focus on lifestyle changes, not crash diets.';
  }
  
  // Heart Health
  if (msg.includes('heart') || msg.includes('cardiac') || msg.includes('cholesterol') || msg.includes('cardiovascular')) {
    return '❤️ **Heart Health:** Eat heart-healthy fats (olive oil, avocados, nuts). Increase fiber from whole grains and vegetables. Limit saturated fats and avoid trans fats. Exercise regularly to strengthen your heart. Manage stress effectively. Quit smoking and limit alcohol. Monitor cholesterol and blood pressure.';
  }
  
  // Hydration
  if (msg.includes('water') || msg.includes('hydration') || msg.includes('drink')) {
    return '💧 **Hydration Tips:** Drink 8 glasses (64 oz) of water daily. Increase intake during exercise or hot weather. Start your day with a glass of water. Carry a reusable water bottle. Eat water-rich foods like fruits and vegetables. Limit sugary drinks and excessive caffeine.';
  }
  
  // General Health
  if (msg.includes('health') || msg.includes('healthy') || msg.includes('wellness')) {
    return '🌟 **Overall Health Tips:** Eat a balanced diet with variety. Exercise regularly (30 min most days). Get 7-9 hours of quality sleep. Manage stress effectively. Stay hydrated. Maintain healthy weight. Schedule regular check-ups. Avoid smoking and limit alcohol. Stay socially connected.';
  }
  
  // Default response with comprehensive topics
  return '🩺 **I can help you with:**\n\n• 🥗 Diet & Nutrition advice\n• 💪 Exercise & Fitness tips\n• 🩺 Diabetes management\n• 💓 Blood pressure control\n• 😴 Sleep improvement\n• 🧘 Stress & anxiety management\n• ⚖️ Weight management\n• ❤️ Heart health\n• 💧 Hydration tips\n\n**Ask me anything about these health topics!** For example: "What are healthy eating tips?" or "How can I manage stress?"';
}

// TEST ENDPOINT - Check API Connection (WORKING MODEL)
app.get('/api/test-ai', async (req, res) => {
  try {
    console.log('🧪 Testing Google AI API connection...');
    console.log('API Key:', GOOGLE_AI_API_KEY ? `${GOOGLE_AI_API_KEY.substring(0, 10)}...` : 'NOT SET');
    
    if (!GOOGLE_AI_API_KEY) {
      return res.json({
        success: false,
        message: 'API Key not configured',
        solution: 'Add GOOGLE_AI_API_KEY to .env file'
      });
    }

    // WORKING ENDPOINT - gemini-pro with v1beta
    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GOOGLE_AI_API_KEY}`;
    
    const testResponse = await axios.post(apiUrl, {
      contents: [{
        parts: [{ text: 'Say hello in one sentence and give me a detailed health tip about stress management' }]
      }]
    }, {
      timeout: 10000,
      headers: { 'Content-Type': 'application/json' }
    });

    const aiText = testResponse.data?.candidates?.[0]?.content?.parts?.[0]?.text;

    // Log complete test response
    console.log('\n🔬 Test AI Response:');
    console.log('='.repeat(60));
    console.log(aiText);
    console.log('='.repeat(60));

    res.json({
      success: true,
      message: '✅ Google AI API is working perfectly!',
      apiResponse: aiText,
      status: testResponse.status,
      model: 'gemini-2.5-flash',
      endpoint: 'v1beta (stable model)',
      responseLength: aiText?.length || 0
    });
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
    res.json({
      success: false,
      message: 'API connection failed',
      error: error.message,
      details: error.response?.data,
      status: error.response?.status,
      troubleshooting: {
        apiKey: GOOGLE_AI_API_KEY ? 'Set (check if valid)' : 'Not set',
        workingEndpoint: 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent',
        workingModel: 'gemini-pro',
        note: 'gemini-pro is the stable, working model',
        suggestions: [
          'Verify API key is correct in .env',
          'Model: gemini-pro (most stable)',
          'Endpoint: v1beta/models/gemini-pro:generateContent',
          'Ensure Generative Language API is enabled',
          'Check https://makersuite.google.com/app/apikey'
        ]
      }
    });
  }
});

// DEBUG ENDPOINT - View full chat response
app.get('/api/debug/chat', async (req, res) => {
  try {
    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GOOGLE_AI_API_KEY}`;
    
    const testResponse = await axios.post(apiUrl, {
      contents: [{
        parts: [{ text: 'Give me a detailed 5-sentence response about stress management and meditation techniques' }]
      }],
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 500
      }
    }, {
      timeout: 10000,
      headers: { 'Content-Type': 'application/json' }
    });

    const aiText = testResponse.data?.candidates?.[0]?.content?.parts?.[0]?.text;
    
    res.json({
      success: true,
      response: aiText,
      length: aiText?.length,
      fullResponse: testResponse.data
    });
    
  } catch (error) {
    res.json({
      success: false,
      error: error.message,
      details: error.response?.data
    });
  }
});

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  socket.on('disconnect', () => console.log('Client disconnected:', socket.id));
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  🏥 Medical System Server                                        ║
║  ✅ Port: ${PORT}                                                 ║
║  📊 MongoDB: Connected                                           ║
║  🤖 AI: Enabled                                                  ║
║  🔑 API Key: ${GOOGLE_AI_API_KEY ? 'CONFIGURED' : 'NOT SET'}                       ║
╚══════════════════════════════════════════════════════════════════╝
  `);
});