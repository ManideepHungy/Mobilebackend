const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('./generated/prisma');
require('dotenv').config();

const app = express();
// Initialize Prisma with correct options
const prisma = new PrismaClient({
  log: ['query', 'error', 'warn'],
  datasources: {
    db: {
      url: process.env.DATABASE_URL
    }
  }
});

// Add connection error handling
prisma.$on('query', (e) => {
  console.log('Query:', e.query);
  console.log('Duration:', e.duration, 'ms');
});

prisma.$on('error', (e) => {
  console.error('Prisma Error:', e);
});

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const BASE_URL = process.env.BASE_URL || 'http://localhost:4000';

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
  const { email, phone, password, firstName, lastName, organizationId, role } = req.body;
  if (!email || !password || !firstName || !lastName || !organizationId || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, phone, password: hashedPassword, firstName, lastName, organizationId, role },
    });
    res.status(201).json({ message: 'User registered', user: { id: user.id, email: user.email, role: user.role, organizationId: user.organizationId } });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({ error: 'Email or phone already exists' });
    }
    res.status(500).json({ error: 'Registration failed', details: err.message });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Missing email or password' });
  }
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName, role: user.role, organizationId: user.organizationId } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

// Get user by ID endpoint
app.get('/api/users/:id', async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (isNaN(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        organization: {
          select: {
            name: true
          }
        }
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Remove sensitive data
    const { password, resetToken, resetTokenExpiry, ...userData } = user;
    res.json(userData);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Failed to fetch user data', details: err.message });
  }
});

// Update user email endpoint
app.put('/api/users/:id/email', async (req, res) => {
  const userId = parseInt(req.params.id);
  const { email } = req.body;
  if (!email || isNaN(userId)) {
    return res.status(400).json({ error: 'Valid user ID and email are required' });
  }
  // Basic email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  try {
    // Check if email already exists for another user
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing && existing.id !== userId) {
      return res.status(409).json({ error: 'Email already in use' });
    }
    const updated = await prisma.user.update({
      where: { id: userId },
      data: { email },
    });
    res.json({ message: 'Email updated successfully', email: updated.email });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update email', details: err.message });
  }
});

// Forgot password endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      // Return success even if user doesn't exist for security
      return res.json({ message: 'If an account exists, you will receive password reset instructions.' });
    }

    // Generate a random reset token
    const resetToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour from now

    // Store the reset token in the database
    await prisma.user.update({
      where: { email },
      data: {
        resetToken,
        resetTokenExpiry
      }
    });

    // For development, return the reset link in the response
    const resetLink = `hungy://reset-password?token=${resetToken}`;
    console.log('Password reset link:', resetLink);

    res.json({ 
      message: 'If an account exists, you will receive password reset instructions.',
      resetLink // Include the reset link in development
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required' });
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpiry: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the reset token
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiry: null
      }
    });

    res.json({ message: 'Password has been reset successfully' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Change password for authenticated user
app.post('/api/auth/change-password', async (req, res) => {
  const { userId, newPassword } = req.body;
  if (!userId || !newPassword) {
    return res.status(400).json({ error: 'userId and newPassword are required' });
  }
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    console.log('Updating password for user:', userId, newPassword);
    await prisma.user.update({
      where: { id: parseInt(userId) },
      data: { password: hashedPassword },
    });
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update password', details: err.message });
  }
});

// Get all organizations
app.get('/api/organizations', async (req, res) => {
  try {
    console.log('Attempting to fetch organizations...');
    console.log('Database URL:', process.env.DATABASE_URL ? 'URL exists' : 'URL missing');
    
    const orgs = await prisma.organization.findMany({ 
      select: { id: true, name: true }
    });
    
    console.log('Organizations fetched:', orgs);
    res.json(orgs);
  } catch (err) {
    console.error('Error fetching organizations:', err);
    console.error('Error stack:', err.stack);
    
    // Handle specific Prisma errors
    if (err.code === 'P1001') {
      return res.status(503).json({ error: 'Database connection timeout', details: err.message });
    }
    if (err.code === 'P1002') {
      return res.status(503).json({ error: 'Database connection error', details: err.message });
    }
    
    res.status(500).json({ error: 'Failed to fetch organizations', details: err.message });
  }
});

// GET /api/organizations/:id - get organization details by ID
app.get('/api/organizations/:id', async (req, res) => {
  try {
    const org = await prisma.organization.findUnique({
      where: { id: parseInt(req.params.id) }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    res.json(org);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch organization' });
  }
});

// Helper to parse YYYY-MM-DD as UTC date
function parseUTCDate(dateStr) {
  if (!dateStr) return null;
  return new Date(dateStr + 'T00:00:00Z');
}

// Get all available shifts (grouped by category, with date/week filtering and recurring shift logic)
app.get('/api/shifts', async (req, res) => {
  try {
    const { date, week, organizationId, category } = req.query;
    // console.log('Shifts request:', { date, week, organizationId, category });
    let dates = [];
    if (date) {
      // Use UTC date parsing
      dates = [parseUTCDate(date)];
    } else if (week) {
      // Week: get all 7 days starting from week (assume week is Monday)
      const start = parseUTCDate(week);
      for (let i = 0; i < 7; i++) {
        const d = new Date(start);
        d.setUTCDate(start.getUTCDate() + i);
        dates.push(d);
      }
    } else {
      // Default: today (UTC)
      const today = new Date();
      dates = [new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()))];
    }
    dates = dates.map(d => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())));

    // Build filters
    const shiftWhere = {
      startTime: {
        gte: dates[0],
        lt: (() => { const nextDay = new Date(dates[dates.length - 1]); nextDay.setDate(nextDay.getDate() + 1); return nextDay; })(),
      },
    };
    if (organizationId) shiftWhere.organizationId = parseInt(organizationId);
    if (category) {
      // Find the shiftCategoryId for this org/category
      const cat = await prisma.shiftCategory.findFirst({
        where: { name: category, ...(organizationId ? { organizationId: parseInt(organizationId) } : {}) },
      });
      if (cat) shiftWhere.shiftCategoryId = cat.id;
      else shiftWhere.shiftCategoryId = -1; // No such category, will return empty
    }

    // Fetch all one-off shifts for the selected dates
    const shifts = await prisma.shift.findMany({
      where: shiftWhere,
      include: {
        shiftCategory: true,
        organization: true,
        shiftSignups: true,
      },
      orderBy: { startTime: 'asc' },
    });

    // Fetch all recurring shift templates
    const recurringWhere = {};
    if (organizationId) recurringWhere.organizationId = parseInt(organizationId);
    if (category) {
      const cat = await prisma.shiftCategory.findFirst({
        where: { name: category, ...(organizationId ? { organizationId: parseInt(organizationId) } : {}) },
      });
      if (cat) recurringWhere.shiftCategoryId = cat.id;
      else recurringWhere.shiftCategoryId = -1;
    }
    const recurringTemplates = await prisma.recurringShift.findMany({
      where: recurringWhere,
      include: {
        shiftCategory: true,
        organization: true,
      },
    });

    // Map one-off shifts to the same format
    const mappedShifts = shifts.map(shift => ({
      id: shift.id,
      name: shift.name,
      time: `${formatTime(shift.startTime)}–${formatTime(shift.endTime)}`,
      location: shift.organization.name,
      slots: shift.slots - shift.shiftSignups.length,
      icon: getShiftIcon(shift.shiftCategory.name, shift.name),
      category: shift.shiftCategory.name,
      isRecurring: false,
      date: shift.startTime.toISOString().slice(0, 10),
    }));

    // For each date, generate virtual shifts from recurring templates
    let virtualShifts = [];
    for (const d of dates) {
      const dayOfWeek = d.getDay();
      for (const template of recurringTemplates) {
        if (template.dayOfWeek === dayOfWeek) {
          // Set start and end time for this date
          const start = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), new Date(template.startTime).getUTCHours(), new Date(template.startTime).getUTCMinutes()));
          const end = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), new Date(template.endTime).getUTCHours(), new Date(template.endTime).getUTCMinutes()));

          // Check if a real shift instance exists for this date/template
          const realShift = shifts.find(s =>
            s.name === template.name &&
            s.shiftCategoryId === template.shiftCategoryId &&
            s.organizationId === template.organizationId &&
            s.startTime.getTime() === start.getTime()
          );

          if (!realShift) {
            virtualShifts.push({
              id: `recurring-${template.id}-${d.toISOString().slice(0, 10)}`,
              name: template.name,
              time: `${formatTime(start)}–${formatTime(end)}`,
              location: template.organization.name,
              slots: template.slots,
              icon: getShiftIcon(template.shiftCategory.name, template.name),
              category: template.shiftCategory.name,
              isRecurring: true,
              date: d.toISOString().slice(0, 10),
            });
          }
        }
      }
    }

    // Combine and group by category
    const allShifts = [...mappedShifts, ...virtualShifts];
    const grouped = {};
    for (const shift of allShifts) {
      const cat = shift.category;
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push(shift);
    }
    // console.log('Grouped shifts:', grouped);
    res.json(grouped);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch shifts', details: err.message });
  }
});

// Get all shift categories for an organization
app.get('/api/shift-categories', async (req, res) => {
  try {
    const { organizationId } = req.query;
    if (!organizationId) return res.status(400).json({ error: 'organizationId is required' });
    const categories = await prisma.shiftCategory.findMany({
      where: { organizationId: parseInt(organizationId) },
      select: { id: true, name: true, icon: true },
      orderBy: { name: 'asc' },
    });
    res.json(categories);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch shift categories', details: err.message });
  }
});

// POST /api/shift-signup endpoint
app.post('/api/shift-signup', async (req, res) => {
  try {
    const { shiftId, userId, date } = req.body;
    if (!shiftId || !userId) return res.status(400).json({ error: 'shiftId and userId are required' });
    let realShiftId = shiftId;
    // Handle recurring shift registration
    if (typeof shiftId === 'string' && shiftId.startsWith('recurring-')) {
      // Parse recurring shift id and date
      const parts = shiftId.split('-');
      const recurringId = parseInt(parts[1]);
      const shiftDate = date || (parts.length > 2 ? parts[2] : null);
      if (!recurringId || !shiftDate) return res.status(400).json({ error: 'Invalid recurring shift id or date' });
      
      // Find the recurring template
      const template = await prisma.recurringShift.findUnique({ where: { id: recurringId } });
      if (!template) return res.status(404).json({ error: 'Recurring shift not found' });
      
      // Check if a real shift already exists for this date/template
      const start = parseUTCDate(shiftDate);
      start.setUTCHours(new Date(template.startTime).getUTCHours(), new Date(template.startTime).getUTCMinutes(), 0, 0);
      const end = parseUTCDate(shiftDate);
      end.setUTCHours(new Date(template.endTime).getUTCHours(), new Date(template.endTime).getUTCMinutes(), 0, 0);
      
      let realShift = await prisma.shift.findFirst({
        where: {
          name: template.name,
          shiftCategoryId: template.shiftCategoryId,
          organizationId: template.organizationId,
          startTime: start,
        },
        include: {
          shiftSignups: true
        }
      });

      if (!realShift) {
        // Create the real shift instance
        realShift = await prisma.shift.create({
          data: {
            name: template.name,
            shiftCategoryId: template.shiftCategoryId,
            startTime: start,
            endTime: end,
            location: template.location,
            slots: template.slots,
            organizationId: template.organizationId,
          },
          include: {
            shiftSignups: true
          }
        });
      }

      // Check available slots before allowing registration
      const availableSlots = realShift.slots - realShift.shiftSignups.length;
      if (availableSlots <= 0) {
        return res.status(400).json({ error: 'No slots available for this shift' });
      }

      realShiftId = realShift.id;
    } else {
      // For one-off shifts, check available slots
      const shift = await prisma.shift.findUnique({
        where: { id: parseInt(shiftId) },
        include: {
          shiftSignups: true
        }
      });
      
      if (!shift) return res.status(404).json({ error: 'Shift not found' });
      
      const availableSlots = shift.slots - shift.shiftSignups.length;
      if (availableSlots <= 0) {
        return res.status(400).json({ error: 'No slots available for this shift' });
      }
    }

    // Check if user already signed up for this shift
    const existing = await prisma.shiftSignup.findFirst({
      where: { userId: parseInt(userId), shiftId: typeof realShiftId === 'string' ? parseInt(realShiftId) : realShiftId },
    });
    if (existing) return res.status(409).json({ error: 'Already registered for this shift' });

    // Create the signup
    const signup = await prisma.shiftSignup.create({
      data: {
        userId: parseInt(userId),
        shiftId: typeof realShiftId === 'string' ? parseInt(realShiftId) : realShiftId,
      },
    });

    res.json({ message: 'Registered', signup });
  } catch (err) {
    res.status(500).json({ error: 'Failed to register for shift', details: err.message });
  }
});

// Helper to format time as e.g. 7:00 AM
function formatTime(dateStr) {
  const date = new Date(dateStr);
  let h = date.getHours();
  const m = date.getMinutes();
  const ampm = h >= 12 ? 'PM' : 'AM';
  h = h % 12;
  h = h ? h : 12;
  return `${h}:${m.toString().padStart(2, '0')} ${ampm}`;
}

// Helper to get emoji icon for shift category/name
function getShiftIcon(category, name) {
  if (category === 'Daily Meal Program') {
    if (name.toLowerCase().includes('breakfast')) return '☕';
    if (name.toLowerCase().includes('lunch')) return '🍲';
    if (name.toLowerCase().includes('supper')) return '🍛';
    return '🍽️';
  }
  if (category === 'Grab & Go') return '🧺';
  if (category === 'Special Projects') return '🌱';
  if (category === 'SHP Volunteers') return '👥';
  return '🕒';
}

// Get all registered shifts for a user (excluding Collection category)
app.get('/api/my-shifts', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ error: 'userId is required' });
    // Find all signups for this user, include shift, category, org
    const signups = await prisma.shiftSignup.findMany({
      where: { userId: parseInt(userId) },
      include: {
        shift: {
          include: {
            shiftCategory: true,
            organization: true,
          },
        },
      },
      orderBy: { id: 'desc' },
    });
    // Filter out Collection category
    // const filtered = signups.filter(s => s.shift.shiftCategory.name !== 'Collection');
    // Map to a simpler format for frontend
    const result = signups.map(s => ({
      signupId: s.id,
      shiftId: s.shift.id,
      name: s.shift.name,
      date: s.shift.startTime,
      time: `${formatTime(s.shift.startTime)}–${formatTime(s.shift.endTime)}`,
      location: s.shift.organization.name,
      slots: s.shift.slots,
      icon: getShiftIcon(s.shift.shiftCategory.name, s.shift.name),
      category: s.shift.shiftCategory.name,
      checkIn: s.checkIn,
      checkOut: s.checkOut,
      mealsServed: s.mealsServed,
      organization: s.shift.organization.name,
      organizationId: s.shift.organizationId,
    }));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch registered shifts', details: err.message });
  }
});

// Checkout endpoint for a shift
app.post('/api/my-shifts/checkout', async (req, res) => {
  try {
    const { shiftId, userId, mealsCount } = req.body;
    console.log('Checkout request:', { shiftId, userId, mealsCount });
    if (!shiftId || !userId) return res.status(400).json({ error: 'shiftId and userId are required' });

    const shift = await prisma.shiftSignup.findUnique({
      where: { id: parseInt(shiftId) },
    });
    console.log('shiftSignup lookup result:', shift);

    if (!shift) return res.status(404).json({ error: 'Shift not found' });

    const signup = await prisma.shiftSignup.findFirst({
      where: { userId: parseInt(userId), id: parseInt(shiftId) },
    });
    console.log('ShiftSignup lookup result:', signup);

    if (!signup) return res.status(404).json({ error: 'Shift signup not found' });

    const updatedSignup = await prisma.shiftSignup.update({
      where: { id: signup.id },
      data: { checkOut: new Date(), mealsServed: mealsCount || 0 },
    });

    res.json({ message: 'Checked out successfully', signup: updatedSignup });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed to checkout', details: err.message });
  }
});

// Check-in endpoint for a shift
app.post('/api/my-shifts/checkin', async (req, res) => {
  try {
    const { shiftId, userId } = req.body;
    console.log('Checkin request:', { shiftId, userId });
    if (!shiftId || !userId) return res.status(400).json({ error: 'shiftId and userId are required' });

    const signup = await prisma.shiftSignup.findFirst({
      where: { userId: parseInt(userId), id: parseInt(shiftId) },
    });
    console.log('ShiftSignup lookup result:', signup);

    if (!signup) return res.status(404).json({ error: 'Shift signup not found' });

    const updatedSignup = await prisma.shiftSignup.update({
      where: { id: signup.id },
      data: { checkIn: new Date() },
    });

    res.json({ message: 'Checked in successfully', signup: updatedSignup });
  } catch (err) {
    console.error('Checkin error:', err);
    res.status(500).json({ error: 'Failed to check in', details: err.message });
  }
});

// Get all donors
app.get('/api/donors', async (req, res) => {
  try {
    const donors = await prisma.donor.findMany({
      select: { id: true, name: true, location: true, contactInfo: true, kitchenId: true },
      orderBy: { name: 'asc' },
    });
    res.json(donors);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch donors', details: err.message });
  }
});

// Create new donor
app.post('/api/donors', async (req, res) => {
  try {
    const { name, location, contactInfo, kitchenId } = req.body;
    
    if (!name || !kitchenId) {
      return res.status(400).json({ error: 'name and kitchenId are required' });
    }

    // Check if donor with same name already exists
    const existingDonor = await prisma.donor.findUnique({
      where: { name },
    });
    
    if (existingDonor) {
      return res.status(409).json({ error: 'A donor with this name already exists' });
    }

    // Verify the kitchen/organization exists
    const organization = await prisma.organization.findUnique({
      where: { id: parseInt(kitchenId) },
    });
    
    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    const donor = await prisma.donor.create({
      data: {
        name,
        location: location || null,
        contactInfo: contactInfo || null,
        kitchenId: parseInt(kitchenId),
      },
      select: { id: true, name: true, location: true, contactInfo: true, kitchenId: true },
    });

    res.status(201).json(donor);
  } catch (err) {
    console.error('Error creating donor:', err);
    res.status(500).json({ error: 'Failed to create donor', details: err.message });
  }
});

// Get all donation categories for a kitchen/organization
app.get('/api/donation-categories', async (req, res) => {
  try {
    const { organizationId } = req.query;
    if (!organizationId) return res.status(400).json({ error: 'organizationId is required' });
    const categories = await prisma.donationCategory.findMany({
      where: { organizationId: parseInt(organizationId) },
      select: { id: true, name: true, icon: true },
      orderBy: { name: 'asc' },
    });
    res.json(categories);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch donation categories', details: err.message });
  }
});

// Add new donation category for an organization
app.post('/api/donation-categories', async (req, res) => {
  const { name, icon, organizationId } = req.body;
  if (!name || !icon || !organizationId) {
    return res.status(400).json({ error: 'name, icon, and organizationId are required' });
  }
  try {
    // Check for uniqueness within the organization
    const existing = await prisma.donationCategory.findFirst({
      where: { name, organizationId: parseInt(organizationId) },
    });
    if (existing) {
      return res.status(409).json({ error: 'Category with this name already exists for this organization' });
    }
    const category = await prisma.donationCategory.create({
      data: {
        name,
        icon,
        organizationId: parseInt(organizationId),
      },
      select: { id: true, name: true, icon: true },
    });
    res.status(201).json(category);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create donation category', details: err.message });
  }
});

// POST /api/donations - create donation entries for a shift and donor
app.post('/api/donations', async (req, res) => {
  try {
    const { shiftId, donorId, entries, shiftSignupId } = req.body;
    console.log('Donations request:', { shiftId, donorId, entries, shiftSignupId });
    if (!shiftId || !donorId || !Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ error: 'shiftId, donorId, and entries are required' });
    }
    // Find the shift to get organizationId
    const shift = await prisma.shift.findUnique({ where: { id: parseInt(shiftId) } });
    if (!shift) return res.status(404).json({ error: 'Shift not found' });
    const organizationId = shift.organizationId;

    // Calculate total weight across all entries
    const totalWeight = entries.reduce((sum, entry) => sum + entry.weightKg, 0);

    // Create a single donation record
    const donation = await prisma.donation.create({
      data: {
        shiftId: parseInt(shiftId),
        organizationId,
        donorId: parseInt(donorId),
        summary: totalWeight,
        ...(shiftSignupId ? { shiftSignupId: parseInt(shiftSignupId) } : {}),
      },
    });

    // Create donation items for each entry
    const donationItems = await Promise.all(
      entries.map(entry =>
        prisma.donationItem.create({
          data: {
            donationId: donation.id,
            categoryId: entry.categoryId,
            weightKg: entry.weightKg,
          },
        })
      )
    );

    res.json({ message: 'Donations recorded', donationId: donation.id, items: donationItems });
  } catch (err) {
    res.status(500).json({ error: 'Failed to record donations', details: err.message });
  }
});

// POST /api/shifts - create a new shift
app.post('/api/shifts', async (req, res) => {
  try {
    const { name, shiftCategoryId, startTime, endTime, location, slots, organizationId } = req.body;
    if (!name || !shiftCategoryId || !startTime || !endTime || !location || !slots || !organizationId) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const shift = await prisma.shift.create({
      data: {
        name,
        shiftCategoryId: parseInt(shiftCategoryId),
        startTime: new Date(startTime),
        endTime: new Date(endTime),
        location,
        slots: parseInt(slots),
        organizationId: parseInt(organizationId),
      },
      include: {
        shiftCategory: true,
        organization: true,
      },
    });

    res.status(201).json(shift);
  } catch (err) {
    console.error('Failed to create shift:', err);
    res.status(500).json({ error: 'Failed to create shift', details: err.message });
  }
});

// POST /api/collection-shift/start - Start a collection shift for today
app.post('/api/collection-shift/start', async (req, res) => {
  try {
    const { userId, organizationId } = req.body;
    if (!userId || !organizationId) return res.status(400).json({ error: 'userId and organizationId are required' });

    // Find the 'Collection' shift category for this org
    const collectionCategory = await prisma.shiftCategory.findFirst({
      where: { name: 'Collection', organizationId: parseInt(organizationId) },
    });
    if (!collectionCategory) return res.status(404).json({ error: 'Collection category not found for this organization' });

    // Find or create today's Collection shift
    const today = new Date();
    const startOfDay = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate(), 0, 0, 0));
    const endOfDay = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate(), 23, 59, 59));
    let shift = await prisma.shift.findFirst({
      where: {
        shiftCategoryId: collectionCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: startOfDay, lte: endOfDay },
      },
    });
    console.log('Collection shift lookup result:', shift);
    if (!shift) {
      // Create a new shift for today (default time: now to now+2h, slots: 100)
      const now = new Date();
      const end = new Date(now.getTime() + 2 * 60 * 60 * 1000);
      shift = await prisma.shift.create({
        data: {
          name: 'Collection Shift',
          shiftCategoryId: collectionCategory.id,
          startTime: now,
          endTime: end,
          location: 'Various',
          slots: 100,
          organizationId: parseInt(organizationId),
        },
      });
    }

    // Create a new ShiftSignup for this user for this shift
    const signup = await prisma.shiftSignup.create({
      data: {
        userId: parseInt(userId),
        shiftId: shift.id,
        checkIn: new Date(),
      },
    });

    res.json({ shift, signup });
  } catch (err) {
    console.error('Error starting collection shift:', err);
    res.status(500).json({ error: 'Failed to start collection shift', details: err.message });
  }
});

// ADMIN: Get all users for an org except volunteers
app.get('/api/admin/org-users', async (req, res) => {
  try {
    const { organizationId } = req.query;
    if (!organizationId) return res.status(400).json({ error: 'organizationId is required' });
    const users = await prisma.user.findMany({
      where: {
        organizationId: parseInt(organizationId),
        // role: { not: 'VOLUNTEER' },
      },
      select: { id: true, firstName: true, lastName: true, email: true, role: true },
      orderBy: { firstName: 'asc' },
    });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users', details: err.message });
  }
});

// ADMIN: Get all shifts and signups for a date/category/org (with recurring logic)
app.get('/api/admin/shifts', async (req, res) => {
  try {
    const { date, category, organizationId } = req.query;
    if (!date || !category || !organizationId) return res.status(400).json({ error: 'date, category, and organizationId are required' });
    // Find the shiftCategoryId
    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });
    // Find all real shifts for that date/category/org
    const start = new Date(date + 'T00:00:00Z');
    const end = new Date(date + 'T23:59:59Z');
    const realShifts = await prisma.shift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
      include: {
        shiftSignups: {
          include: { user: true },
        },
      },
      orderBy: { startTime: 'asc' },
    });
    // Find recurring templates for this category/org
    const dayOfWeek = start.getUTCDay();
    const recurringTemplates = await prisma.recurringShift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        dayOfWeek,
      },
      include: {
        shiftCategory: true,
        organization: true,
      },
    });
    // For each recurring template, if no real shift exists for this date/template, generate a virtual shift
    let virtualShifts = [];
    for (const template of recurringTemplates) {
      const startTime = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate(), new Date(template.startTime).getUTCHours(), new Date(template.startTime).getUTCMinutes()));
      const endTime = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate(), new Date(template.endTime).getUTCHours(), new Date(template.endTime).getUTCMinutes()));
      const real = realShifts.find(s => s.name === template.name && s.startTime.getTime() === startTime.getTime());
      if (!real) {
        virtualShifts.push({
          id: `recurring-${template.id}-${date}`,
          name: template.name,
          time: `${formatTime(startTime)}–${formatTime(endTime)}`,
          location: template.organization.name,
          slots: template.slots,
          icon: getShiftIcon(template.shiftCategory.name, template.name),
          category: template.shiftCategory.name,
          isRecurring: true,
          date,
          shiftSignups: [],
        });
      }
    }
    // Map real shifts to the same format
    const mappedShifts = realShifts.map(shift => ({
      id: shift.id,
      name: shift.name,
      time: `${formatTime(shift.startTime)}–${formatTime(shift.endTime)}`,
      location: shift.organization ? shift.organization.name : '',
      slots: shift.slots - shift.shiftSignups.length,
      icon: getShiftIcon(shift.shiftCategory.name, shift.name),
      category: shift.shiftCategory.name,
      isRecurring: false,
      date: shift.startTime.toISOString().slice(0, 10),
      shiftSignups: shift.shiftSignups,
    }));
    res.json([...mappedShifts, ...virtualShifts]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admin shifts', details: err.message });
  }
});

// ADMIN: Check in a user for a shift (by userId, date, category, organizationId)
app.post('/api/admin/checkin', async (req, res) => {
  try {
    let { userId, date, category, organizationId } = req.body;
    if (!userId || !date || !category || !organizationId) {
      return res.status(400).json({ error: 'userId, date, category, and organizationId are required' });
    }
    // Find the shiftCategoryId
    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });
    // Find or create the real shift for this date/category/org
    const start = new Date(date + 'T00:00:00Z');
    const end = new Date(date + 'T23:59:59Z');
    let realShift = await prisma.shift.findFirst({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
    });
    if (!realShift) {
      // Create a new shift for this date/category/org (default time: 9am-5pm, slots: 100)
      const shiftStart = new Date(date + 'T09:00:00Z');
      const shiftEnd = new Date(date + 'T17:00:00Z');
      realShift = await prisma.shift.create({
        data: {
          name: shiftCategory.name,
          shiftCategoryId: shiftCategory.id,
          startTime: shiftStart,
          endTime: shiftEnd,
          location: 'Default',
          slots: 100,
          organizationId: parseInt(organizationId),
        },
      });
    }
    // Find or create the signup for this user/shift
    let signup = await prisma.shiftSignup.findFirst({
      where: { userId: parseInt(userId), shiftId: realShift.id },
    });
    if (!signup) {
      signup = await prisma.shiftSignup.create({
        data: {
          userId: parseInt(userId),
          shiftId: realShift.id,
          checkIn: new Date(),
        },
      });
    } else {
      signup = await prisma.shiftSignup.update({
        where: { id: signup.id },
        data: { checkIn: new Date() },
      });
    }
    res.json({
      id: signup.id,
      checkIn: signup.checkIn,
      checkOut: signup.checkOut,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check in', details: err.message });
  }
});

// ADMIN: Check out a user for a shift (by userId, date, category, organizationId)
app.post('/api/admin/checkout', async (req, res) => {
  try {
    let { userId, date, category, organizationId } = req.body;
    if (!userId || !date || !category || !organizationId) {
      return res.status(400).json({ error: 'userId, date, category, and organizationId are required' });
    }
    // Find the shiftCategoryId
    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });
    // Find the real shift for this date/category/org
    const start = new Date(date + 'T00:00:00Z');
    const end = new Date(date + 'T23:59:59Z');
    const realShift = await prisma.shift.findFirst({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
    });
    if (!realShift) {
      return res.status(404).json({ error: 'No shift found for this date/category/org' });
    }
    // Find the signup for this user/shift
    let signup = await prisma.shiftSignup.findFirst({
      where: { userId: parseInt(userId), shiftId: realShift.id },
    });
    if (!signup) {
      return res.status(404).json({ error: 'No signup found for this user/shift' });
    }
    signup = await prisma.shiftSignup.update({
      where: { id: signup.id },
      data: { checkOut: new Date() },
    });
    res.json({
      id: signup.id,
      checkIn: signup.checkIn,
      checkOut: signup.checkOut,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check out', details: err.message });
  }
});

// ADMIN: Get a user's shift signup for a date/category/org
app.get('/api/admin/user-shift-signup', async (req, res) => {
  try {
    const { userId, date, category, organizationId } = req.query;
    if (!userId || !date || !category || !organizationId) {
      return res.status(400).json({ error: 'userId, date, category, and organizationId are required' });
    }
    // Find the shiftCategoryId
    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });
    // Find all real shifts for that date/category/org
    const start = new Date(date + 'T00:00:00Z');
    const end = new Date(date + 'T23:59:59Z');
    const realShift = await prisma.shift.findFirst({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
    });
    if (!realShift) {
      // No real shift for this date/category/org
      return res.json(null);
    }
    // Find the signup for this user/shift
    const signup = await prisma.shiftSignup.findFirst({
      where: { userId: parseInt(userId), shiftId: realShift.id },
    });
    if (!signup) return res.json(null);
    res.json({
      id: signup.id,
      checkIn: signup.checkIn,
      checkOut: signup.checkOut,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user shift signup', details: err.message });
  }
});

// ADMIN: Submit a meal count (creates a new ShiftSignup with mealsServed)
app.post('/api/admin/meals-count', async (req, res) => {
  try {
    const { userId, date, category, organizationId, mealsServed } = req.body;
    if (!userId || !date || !category || !organizationId || !mealsServed) {
      return res.status(400).json({ error: 'userId, date, category, organizationId, and mealsServed are required' });
    }
    // Find the shiftCategoryId
    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });
    // Find or create the real shift for this date/category/org
    const start = new Date(date + 'T00:00:00Z');
    const end = new Date(date + 'T23:59:59Z');
    let realShift = await prisma.shift.findFirst({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
    });
    if (!realShift) {
      // Create a new shift for this date/category/org (default time: 9am-5pm, slots: 100)
      const shiftStart = new Date(date + 'T09:00:00Z');
      const shiftEnd = new Date(date + 'T17:00:00Z');
      realShift = await prisma.shift.create({
        data: {
          name: shiftCategory.name,
          shiftCategoryId: shiftCategory.id,
          startTime: shiftStart,
          endTime: shiftEnd,
          location: 'Default',
          slots: 100,
          organizationId: parseInt(organizationId),
        },
      });
    }
    // Create a new ShiftSignup with mealsServed
    const signup = await prisma.shiftSignup.create({
      data: {
        userId: parseInt(userId),
        shiftId: realShift.id,
        mealsServed: parseInt(mealsServed),
      },
    });
    res.json({
      id: signup.id,
      mealsServed: signup.mealsServed,
      createdAt: signup.createdAt,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit meal count', details: err.message });
  }
});

// ADMIN: Get all meal count entries for a user/date/category/org
app.get('/api/admin/meals-count-entries', async (req, res) => {
  try {
    const { userId, date, category, organizationId } = req.query;
    if (!userId || !date || !category || !organizationId) {
      return res.status(400).json({ error: 'userId, date, category, and organizationId are required' });
    }
    // Find the shiftCategoryId
    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });
    // Find the real shift for this date/category/org
    const start = new Date(date + 'T00:00:00Z');
    const end = new Date(date + 'T23:59:59Z');
    const realShift = await prisma.shift.findFirst({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
    });
    if (!realShift) return res.json([]);
    // Get all ShiftSignup entries for this user/shift with mealsServed set
    const signups = await prisma.shiftSignup.findMany({
      where: {
        userId: parseInt(userId),
        shiftId: realShift.id,
        mealsServed: { not: null },
      },
      orderBy: { createdAt: 'desc' },
    });
    res.json(signups.map(s => ({
      id: s.id,
      mealsServed: s.mealsServed,
      createdAt: s.createdAt,
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch meal count entries', details: err.message });
  }
});

// ADMIN: Edit a meal count entry (update mealsServed)
app.patch('/api/admin/meals-count-entry/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { mealsServed } = req.body;
    if (!mealsServed || isNaN(mealsServed)) {
      return res.status(400).json({ error: 'mealsServed is required and must be a number' });
    }
    const updated = await prisma.shiftSignup.update({
      where: { id: parseInt(id) },
      data: { mealsServed: parseInt(mealsServed) },
    });
    res.json({ id: updated.id, mealsServed: updated.mealsServed, createdAt: updated.createdAt });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update meal count entry', details: err.message });
  }
});

// ADMIN: Delete a meal count entry
app.delete('/api/admin/meals-count-entry/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.shiftSignup.delete({ where: { id: parseInt(id) } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete meal count entry', details: err.message });
  }
});

// Get all donations for a shift, with donor and category info (for summary modal)
app.get('/api/donations/by-shift', async (req, res) => {
  try {
    const { shiftId, shiftSignupId } = req.query;
    if (!shiftId) return res.status(400).json({ error: 'shiftId is required' });

    const where = { shiftId: parseInt(shiftId) };
    if (shiftSignupId) where.shiftSignupId = parseInt(shiftSignupId);

    const donations = await prisma.donation.findMany({
      where,
      include: {
        donor: true,
        items: { include: { category: true } }
      },
      orderBy: { createdAt: 'asc' }
    });

    // Flatten for frontend: one entry per donor/category/weight
    const result = [];
    for (const donation of donations) {
      for (const item of donation.items) {
        result.push({
          donorName: donation.donor.name,
          categoryName: item.category.name,
          weightKg: item.weightKg,
          createdAt: donation.createdAt
        });
      }
    }
    console.log('Donations result:', result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch donations', details: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Server accessible at:`);
  console.log(`- http://localhost:${PORT}`);
  console.log(`- http://127.0.0.1:${PORT}`);
  console.log(`- http://172.20.10.2:${PORT}`);  // Your computer's IP
}); 