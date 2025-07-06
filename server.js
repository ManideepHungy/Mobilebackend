const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('./generated/prisma');
const CloudflareR2Service = require('./cloudflareR2');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const { DateTime } = require('luxon');
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

// Email transport setup (configure your SMTP in .env)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

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

// Register step 2 endpoint (with terms acceptance)
app.post('/api/auth/register-step2', async (req, res) => {
  const { 
    firstName, 
    lastName, 
    email, 
    phone, 
    password, 
    organizationId, 
    role, 
    termsAndConditionsId, 
    signature 
  } = req.body;

  if (!firstName || !lastName || !email || !password || !organizationId || !role || !termsAndConditionsId || !signature) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Check if terms and conditions exist
    const terms = await prisma.termsAndConditions.findUnique({
      where: { id: termsAndConditionsId }
    });

    if (!terms) {
      return res.status(400).json({ error: 'Invalid terms and conditions' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with PENDING status
    const user = await prisma.user.create({
      data: { 
        email, 
        phone, 
        password: hashedPassword, 
        firstName, 
        lastName, 
        organizationId, 
        role,
        status: 'PENDING'
      },
    });

    // Fetch organization name
    const org = await prisma.organization.findUnique({ where: { id: organizationId } });
    const orgName = org ? org.name : 'your kitchen';

    // Fetch up to 2 admin emails for this organization
    const admins = await prisma.user.findMany({
      where: {
        organizationId: organizationId,
        role: 'ADMIN',
        status: 'APPROVED',
      },
      select: { email: true },
      take: 2,
    });
    const adminEmails = admins.map(a => a.email).filter(Boolean);
    let adminContactText = '';
    if (adminEmails.length > 0) {
      adminContactText = `\nIf you do not receive a welcome email after the waiting period, you can contact your kitchen admin at: ${adminEmails.join(', ')}`;
    }

    // Generate signed agreement as PDF and upload to R2
    let signedDocumentUrl = null;
    try {
      const doc = new PDFDocument({ margin: 40 });
      let buffers = [];
      doc.on('data', buffers.push.bind(buffers));
      
      // Create a promise to wait for PDF generation and upload
      const pdfPromise = new Promise(async (resolve, reject) => {
        doc.on('end', async () => {
          try {
            const pdfBuffer = Buffer.concat(buffers);
      const uploadResult = await CloudflareR2Service.uploadSignedDocument(
              pdfBuffer,
        user.id.toString(),
        organizationId.toString()
      );
            resolve(uploadResult.url);
    } catch (uploadError) {
            console.error('Failed to upload signed PDF:', uploadError);
            reject(uploadError);
          }
        });
      });

      // PDF content
      doc.fontSize(18).text('SIGNED AGREEMENT', { align: 'center' });
      doc.moveDown();
      doc.fontSize(12).text('User Information:', { underline: true });
      doc.text(`- Name: ${firstName} ${lastName}`);
      doc.text(`- Email: ${email}`);
      doc.text(`- Organization: ${orgName}`);
      doc.text(`- Role: ${role}`);
      doc.moveDown();
      doc.text('Terms & Conditions:', { underline: true });
      doc.text(`- Document: ${terms.title}`);
      doc.text(`- Version: ${terms.version}`);
      doc.text(`- Original URL: ${terms.fileUrl}`);
      doc.moveDown();
      doc.text(`Signed Date: ${new Date().toISOString()}`);
      doc.text(`IP Address: ${req.ip || 'unknown'}`);
      doc.text(`User Agent: ${req.get('User-Agent') || 'unknown'}`);
      doc.moveDown(2);
      doc.fontSize(14).text('Digital Signature:', { underline: true });
      doc.moveDown();
      doc.fontSize(16).text(signature, { align: 'right' });
      doc.moveDown();
      doc.fontSize(10).text('This document confirms that the above user has read and agreed to the terms and conditions.', { align: 'center' });
      doc.end();
      
      // Wait for PDF generation and upload to complete
      signedDocumentUrl = await pdfPromise;
      console.log('Signed document uploaded successfully:', signedDocumentUrl);
    } catch (pdfErr) {
      console.error('Failed to generate/upload signed PDF:', pdfErr);
      // Continue without the signed document URL
    }

    // Create user agreement with the signed document URL
    await prisma.userAgreement.create({
      data: {
        userId: user.id,
        organizationId: organizationId,
        termsAndConditionsId: termsAndConditionsId,
        signature: signature,
        signedDocumentUrl: signedDocumentUrl,
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
      }
    });

    // Send registration confirmation email to user
    try {
      await transporter.sendMail({
        from: process.env.SMTP_FROM || 'no-reply@hungy.org',
        to: email,
        subject: `Thank you for registering for ${orgName} (Pending Approval)` ,
        text: `Hello ${firstName},\n\nThank you for registering as a volunteer for ${orgName}.\n\nYour registration is currently pending admin approval. Admins review new registrations Monday to Friday, 9am-5pm. Approval may take 1-2 business days.\n\nIf you do not receive a welcome email saying you are approved after the waiting period, you can contact your kitchen admin.${adminContactText}\n\nBest regards,\n${orgName} Team`,
        html: `<p>Hello ${firstName},</p><p>Thank you for registering as a volunteer for <b>${orgName}</b>.</p><p>Your registration is currently <b>pending admin approval</b>.<br>Admins review new registrations <b>Monday to Friday, 9am-5pm</b>.<br>Approval may take <b>1-2 business days</b>.</p><p>If you do not receive a welcome email saying you are approved after the waiting period, you can contact your kitchen admin:<br><b>${adminEmails.join('<br>')}</b></p><p>Best regards,<br>${orgName} Team</p>`
      });
    } catch (emailErr) {
      console.error('Failed to send registration email:', emailErr);
      // Continue, do not block registration
    }

    // TODO: Send email notification
    // For now, just log the registration
    console.log(`New user registration: ${email} (${firstName} ${lastName}) - Pending approval`);
    if (signedDocumentUrl) {
      console.log(`Signed document uploaded: ${signedDocumentUrl}`);
    }

    res.status(201).json({ 
      message: 'Registration successful. Account pending admin approval.',
      user: { 
        id: user.id, 
        email: user.email, 
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role, 
        organizationId: user.organizationId,
        status: user.status
      },
      signedDocumentUrl: signedDocumentUrl
    });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({ error: 'Email or phone already exists' });
    }
    console.error('Registration error:', err);
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
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        email: user.email, 
        firstName: user.firstName, 
        lastName: user.lastName, 
        role: user.role, 
        organizationId: user.organizationId,
        status: user.status 
      } 
    });
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

// Update user profile endpoint
app.put('/api/users/:id', async (req, res) => {
  const userId = parseInt(req.params.id);
  const { firstName, lastName, email, phone } = req.body;
  
  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Valid user ID is required' });
  }

  try {
    // Check if email already exists for another user (if email is being updated)
    if (email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }
      
      const existing = await prisma.user.findUnique({ where: { email } });
      if (existing && existing.id !== userId) {
        return res.status(409).json({ error: 'Email already in use' });
      }
    }

    const updateData = {};
    if (firstName !== undefined) updateData.firstName = firstName;
    if (lastName !== undefined) updateData.lastName = lastName;
    if (email !== undefined) updateData.email = email;
    if (phone !== undefined) updateData.phone = phone;

    const updated = await prisma.user.update({
      where: { id: userId },
      data: updateData,
    });

    // Remove sensitive data from response
    const { password, resetToken, resetTokenExpiry, ...userData } = updated;
    res.json({ message: 'Profile updated successfully', user: userData });
  } catch (err) {
    console.error('Error updating user profile:', err);
    res.status(500).json({ error: 'Failed to update profile', details: err.message });
  }
});

// Update user password endpoint
app.put('/api/users/:id/password', async (req, res) => {
  const userId = parseInt(req.params.id);
  const { currentPassword, newPassword } = req.body;
  
  if (isNaN(userId) || !currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Valid user ID, current password, and new password are required' });
  }

  try {
    // Get the current user to verify current password
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password
    await prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error updating password:', err);
    res.status(500).json({ error: 'Failed to update password', details: err.message });
  }
});

// Forgot password endpoint - Send verification code
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      // Return success even if user doesn't exist for security
      return res.json({ message: 'If an account exists, you will receive a verification code.' });
    }

    // Generate a 6-digit verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const resetTokenExpiry = new Date(Date.now() + 600000); // 10 minutes from now

    // Store the verification code in the database
    await prisma.user.update({
      where: { email },
      data: {
        resetToken: verificationCode,
        resetTokenExpiry
      }
    });

    // Send verification code via email
    try {
      await transporter.sendMail({
        from: process.env.SMTP_FROM || 'no-reply@hungy.org',
        to: email,
        subject: 'Password Reset Verification Code',
        text: `Hello ${user.firstName},\n\nYou requested a password reset for your Hungy account.\n\nYour verification code is: ${verificationCode}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this password reset, please ignore this email.\n\nBest regards,\nHungy Team`,
        html: `<p>Hello ${user.firstName},</p><p>You requested a password reset for your Hungy account.</p><p><strong>Your verification code is: ${verificationCode}</strong></p><p>This code will expire in 10 minutes.</p><p>If you did not request this password reset, please ignore this email.</p><p>Best regards,<br>Hungy Team</p>`
      });

      console.log(`Verification code sent to ${email}: ${verificationCode}`);

    res.json({ 
        message: 'If an account exists, you will receive a verification code.',
        success: true
    });
    } catch (emailErr) {
      console.error('Failed to send verification email:', emailErr);
      res.status(500).json({ error: 'Failed to send verification code. Please try again.' });
    }
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

// Verify code endpoint
app.post('/api/auth/verify-code', async (req, res) => {
  const { email, verificationCode } = req.body;
  if (!email || !verificationCode) {
    return res.status(400).json({ error: 'Email and verification code are required' });
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        email: email,
        resetToken: verificationCode,
        resetTokenExpiry: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }

    // Generate a temporary token for password reset
    const tempToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const tempTokenExpiry = new Date(Date.now() + 300000); // 5 minutes from now

    // Store the temporary token
    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetToken: tempToken,
        resetTokenExpiry: tempTokenExpiry
      }
    });

    res.json({ 
      message: 'Verification code is valid',
      tempToken: tempToken,
      success: true
    });
  } catch (err) {
    console.error('Verify code error:', err);
    res.status(500).json({ error: 'Failed to verify code' });
  }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  const { tempToken, newPassword } = req.body;
  if (!tempToken || !newPassword) {
    return res.status(400).json({ error: 'Temporary token and new password are required' });
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        resetToken: tempToken,
        resetTokenExpiry: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired temporary token' });
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

// Get user's module permissions for a specific organization
app.get('/api/users/:id/modules', async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { organizationId } = req.query;
    
    if (isNaN(userId) || !organizationId) {
      return res.status(400).json({ error: 'Valid user ID and organizationId are required' });
    }

    const permissions = await prisma.userModulePermission.findMany({
      where: {
        userId: userId,
        organizationId: parseInt(organizationId),
        canAccess: true
      },
      include: {
        module: {
          select: {
            id: true,
            name: true,
            description: true
          }
        }
      }
    });

    res.json(permissions);
  } catch (err) {
    console.error('Error fetching user modules:', err);
    res.status(500).json({ error: 'Failed to fetch user modules', details: err.message });
  }
});

// ===== NEW AVAILABLE SHIFTS ENDPOINTS =====

// Get all organizations
app.get('/api/organizations', async (req, res) => {
  try {
    console.log('Fetching organizations...');
    const orgs = await prisma.organization.findMany({ 
      select: { id: true, name: true }
    });
    console.log('Organizations fetched:', orgs);
    res.json(orgs);
  } catch (err) {
    console.error('Error fetching organizations:', err);
    res.status(500).json({ error: 'Failed to fetch organizations', details: err.message });
  }
});

// Get all shift categories for an organization (excluding Collection and Meals Counting)
app.get('/api/shift-categories', async (req, res) => {
  try {
    const { organizationId } = req.query;
    if (!organizationId) return res.status(400).json({ error: 'organizationId is required' });
    
    const categories = await prisma.shiftCategory.findMany({
      where: { 
        organizationId: parseInt(organizationId),
        name: {
          notIn: ['Collection', 'Meals Counting']
        }
      },
      select: { id: true, name: true, icon: true },
      orderBy: { name: 'asc' },
    });
    res.json(categories);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch shift categories', details: err.message });
  }
});

// Get available shifts with Halifax timezone handling
app.get('/api/shifts', async (req, res) => {
  try {
    console.log('Available Shifts request:', req.query);
    const { date, week, organizationId, category } = req.query;
    
    if (!organizationId) {
      return res.status(400).json({ error: 'organizationId is required' });
    }

    // Parse dates in Halifax timezone
    let dates = [];
    if (date) {
      // Single date
      const halifaxDate = DateTime.fromISO(date, { zone: 'America/Halifax' });
      if (!halifaxDate.isValid) {
        return res.status(400).json({ error: 'Invalid date format' });
      }
      dates = [halifaxDate];
    } else if (week) {
      // Week starting from Monday
      const startDate = DateTime.fromISO(week, { zone: 'America/Halifax' });
      if (!startDate.isValid) {
        return res.status(400).json({ error: 'Invalid week format' });
      }
      // Generate 7 days starting from the provided date
      for (let i = 0; i < 7; i++) {
        dates.push(startDate.plus({ days: i }));
      }
    } else {
      // Default to today
      const today = DateTime.now().setZone('America/Halifax');
      dates = [today];
    }

    // Filter out past dates
    const now = DateTime.now().setZone('America/Halifax');
    dates = dates.filter(d => d >= now.startOf('day'));

    if (dates.length === 0) {
      return res.json({});
    }

    // Get date range for database query
    const startDate = dates[0].startOf('day');
    const endDate = dates[dates.length - 1].endOf('day');

    // Convert to UTC for database query
    const startUTC = startDate.toUTC().toJSDate();
    const endUTC = endDate.toUTC().toJSDate();

    console.log('Date range:', { startDate: startDate.toISO(), endDate: endDate.toISO() });
    console.log('UTC range:', { startUTC, endUTC });

    // Get category filter
    let categoryFilter = {};
    if (category) {
      const shiftCategory = await prisma.shiftCategory.findFirst({
        where: { 
          name: category, 
          organizationId: parseInt(organizationId) 
        },
      });
      if (shiftCategory) {
        categoryFilter.shiftCategoryId = shiftCategory.id;
      } else {
        // Category not found, return empty result
        return res.json({});
      }
    }

    // Fetch real shifts
    const realShifts = await prisma.shift.findMany({
      where: {
        organizationId: parseInt(organizationId),
        startTime: {
          gte: startUTC,
          lte: endUTC,
        },
        ...categoryFilter,
      },
      include: {
        shiftCategory: true,
        organization: true,
        shiftSignups: true,
      },
      orderBy: { startTime: 'asc' },
    });

    console.log('Found real shifts:', realShifts.length);

    // Map real shifts to frontend format
    const mappedShifts = realShifts.map(shift => {
      const halifaxStart = DateTime.fromJSDate(shift.startTime, { zone: 'America/Halifax' });
      const halifaxEnd = DateTime.fromJSDate(shift.endTime, { zone: 'America/Halifax' });
      
      return {
        id: shift.id,
        name: shift.name,
        time: `${halifaxStart.toFormat('h:mm a')}–${halifaxEnd.toFormat('h:mm a')}`,
        startTime: shift.startTime.toISOString(),
        endTime: shift.endTime.toISOString(),
        location: shift.organization.name,
        slots: Math.max(0, shift.slots - shift.shiftSignups.length),
        icon: getShiftIcon(shift.shiftCategory.name, shift.name),
        category: shift.shiftCategory.name,
        isRecurring: false,
        date: halifaxStart.toISODate(),
      };
    });

    // Fetch recurring shift templates
    const recurringTemplates = await prisma.recurringShift.findMany({
      where: {
        organizationId: parseInt(organizationId),
        ...categoryFilter,
      },
      include: {
        shiftCategory: true,
        organization: true,
      },
    });

    console.log('Found recurring templates:', recurringTemplates.length);

    // Generate virtual shifts from recurring templates
    const virtualShifts = [];
    for (const date of dates) {
      const dayOfWeek = date.weekday % 7; // Convert Luxon weekday to DB format
      
      for (const template of recurringTemplates) {
        if (template.dayOfWeek === dayOfWeek) {
          // Check if a real shift already exists for this date/template
          const existingRealShift = realShifts.find(shift => 
            shift.name === template.name &&
            shift.shiftCategoryId === template.shiftCategoryId &&
            shift.organizationId === template.organizationId
          );

          if (!existingRealShift) {
            // Create virtual shift
            const templateStart = DateTime.fromJSDate(template.startTime, { zone: 'America/Halifax' });
            const templateEnd = DateTime.fromJSDate(template.endTime, { zone: 'America/Halifax' });
            
            const virtualStart = date.set({
              hour: templateStart.hour,
              minute: templateStart.minute,
              second: 0,
              millisecond: 0
            });
            const virtualEnd = date.set({
              hour: templateEnd.hour,
              minute: templateEnd.minute,
              second: 0,
              millisecond: 0
            });

            virtualShifts.push({
              id: `recurring-${template.id}-${date.toISODate()}`,
              name: template.name,
              time: `${virtualStart.toFormat('h:mm a')}–${virtualEnd.toFormat('h:mm a')}`,
              startTime: virtualStart.toUTC().toISO(),
              endTime: virtualEnd.toUTC().toISO(),
              location: template.organization.name,
              slots: template.slots,
              icon: getShiftIcon(template.shiftCategory.name, template.name),
              category: template.shiftCategory.name,
              isRecurring: true,
              date: date.toISODate(),
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

    console.log('Returning grouped shifts:', Object.keys(grouped));
    res.json(grouped);
    
  } catch (err) {
    console.error('Error fetching shifts:', err);
    res.status(500).json({ error: 'Failed to fetch shifts', details: err.message });
  }
});

// Register for a shift
app.post('/api/shift-signup', async (req, res) => {
  try {
    const { shiftId, userId, date } = req.body;
    console.log('Shift signup request:', { shiftId, userId, date });
    
    if (!shiftId || !userId) {
      return res.status(400).json({ error: 'shiftId and userId are required' });
    }

    let realShiftId = shiftId;
    let realShift = null;

    // Handle recurring shift registration
    if (typeof shiftId === 'string' && shiftId.startsWith('recurring-')) {
      const parts = shiftId.split('-');
      const recurringId = parseInt(parts[1]);
      const shiftDate = date || (parts.length > 2 ? parts[2] : null);
      
      if (!recurringId || !shiftDate) {
        return res.status(400).json({ error: 'Invalid recurring shift id or date' });
      }
      
      // Find the recurring template
      const template = await prisma.recurringShift.findUnique({ 
        where: { id: recurringId } 
      });
      
      if (!template) {
        return res.status(404).json({ error: 'Recurring shift template not found' });
      }

      // Create start and end times for the specific date
      const templateStart = DateTime.fromJSDate(template.startTime, { zone: 'America/Halifax' });
      const templateEnd = DateTime.fromJSDate(template.endTime, { zone: 'America/Halifax' });
      
      const halifaxDate = DateTime.fromISO(shiftDate, { zone: 'America/Halifax' });
      const shiftStart = halifaxDate.set({
        hour: templateStart.hour,
        minute: templateStart.minute,
        second: 0,
        millisecond: 0
      });
      const shiftEnd = halifaxDate.set({
        hour: templateEnd.hour,
        minute: templateEnd.minute,
        second: 0,
        millisecond: 0
      });

      // Check if a real shift already exists for this date/template
      realShift = await prisma.shift.findFirst({
        where: {
          name: template.name,
          shiftCategoryId: template.shiftCategoryId,
          organizationId: template.organizationId,
          startTime: shiftStart.toUTC().toJSDate(),
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
            startTime: shiftStart.toUTC().toJSDate(),
            endTime: shiftEnd.toUTC().toJSDate(),
            location: template.location,
            slots: template.slots,
            organizationId: template.organizationId,
          },
          include: {
            shiftSignups: true
          }
        });
        console.log('Created new shift from template:', realShift.id);
      }

      realShiftId = realShift.id;
    } else {
      // Handle one-off shift registration
      realShift = await prisma.shift.findUnique({
        where: { id: parseInt(shiftId) },
        include: {
          shiftSignups: true
        }
      });
      
      if (!realShift) {
        return res.status(404).json({ error: 'Shift not found' });
      }
    }
      
    // Check available slots
    const availableSlots = realShift.slots - realShift.shiftSignups.length;
      if (availableSlots <= 0) {
        return res.status(400).json({ error: 'No slots available for this shift' });
    }

    // Check if user already signed up for this shift
    const existingSignup = await prisma.shiftSignup.findFirst({
      where: { 
        userId: parseInt(userId), 
        shiftId: realShiftId 
      },
    });
    
    if (existingSignup) {
      return res.status(409).json({ error: 'Already registered for this shift' });
    }

    // Create the signup
    const signup = await prisma.shiftSignup.create({
      data: {
        userId: parseInt(userId),
        shiftId: realShiftId,
      },
    });

    console.log('Successfully registered user for shift:', signup.id);
    res.json({ message: 'Registered successfully', signup });
    
  } catch (err) {
    console.error('Error registering for shift:', err);
    res.status(500).json({ error: 'Failed to register for shift', details: err.message });
  }
});

// ===== END NEW AVAILABLE SHIFTS ENDPOINTS =====

// Helper to format time as e.g. 7:00 AM (no timezone)
function formatTimeNoTZ(dateStr) {
  const date = new Date(dateStr);
  return date.toLocaleTimeString('en-US', { 
    hour: '2-digit', 
    minute: '2-digit'
  });
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

// Get all registered shifts for a user (excluding Collection and Meals Counting)
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
    // Filter out Collection and Meals Counting categories and completed (checked out) shifts
    const filtered = signups.filter(s =>
      s.shift.shiftCategory.name !== 'Collection' &&
      s.shift.shiftCategory.name !== 'Meals Counting' &&
      !s.checkOut // Only show if not checked out
    );
    // Map to a simpler format for frontend
    const result = filtered.map(s => ({
      signupId: s.id,
      shiftId: s.shift.id,
      name: s.shift.name,
      date: s.shift.startTime,
      time: `${formatTimeNoTZ(s.shift.startTime)}–${formatTimeNoTZ(s.shift.endTime)}`,
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

// Check in to a shift
app.post('/api/my-shifts/checkin', async (req, res) => {
  try {
    const { shiftSignupId, userId } = req.body;
    if (!shiftSignupId || !userId) {
      return res.status(400).json({ error: 'shiftSignupId and userId are required' });
    }
    // Find the signup
    const signup = await prisma.shiftSignup.findUnique({
      where: { id: parseInt(shiftSignupId) },
      include: { user: true }
    });
    if (!signup) {
      return res.status(404).json({ error: 'Shift signup not found' });
    }
    if (signup.checkIn) {
      return res.status(409).json({ error: 'Already checked in' });
    }
    // Set checkIn to current Halifax time
    const halifaxNow = DateTime.now().setZone('America/Halifax');
    const updated = await prisma.shiftSignup.update({
      where: { id: signup.id },
      data: { checkIn: halifaxNow.toJSDate() },
    });
    res.json({ message: 'Checked in successfully', checkIn: updated.checkIn });
  } catch (err) {
    console.error('Check-in error:', err);
    res.status(500).json({ error: 'Failed to check in', details: err.message });
  }
});

// Check out of a shift
app.post('/api/my-shifts/checkout', async (req, res) => {
  try {
    const { shiftSignupId, userId, mealsCount } = req.body;
    if (!shiftSignupId || !userId) {
      return res.status(400).json({ error: 'shiftSignupId and userId are required' });
    }
    // Find the signup
    const signup = await prisma.shiftSignup.findUnique({
      where: { id: parseInt(shiftSignupId) },
      include: { user: true }
    });
    if (!signup) {
      return res.status(404).json({ error: 'Shift signup not found' });
    }
    if (signup.checkOut) {
      return res.status(409).json({ error: 'Already checked out' });
    }
    // Set checkOut to current Halifax time, and mealsServed if provided
    const halifaxNow = DateTime.now().setZone('America/Halifax');
    const updateData = { checkOut: halifaxNow.toJSDate() };
    if (typeof mealsCount === 'number') {
      updateData.mealsServed = mealsCount;
    }
    const updated = await prisma.shiftSignup.update({
      where: { id: signup.id },
      data: updateData,
    });
    res.json({ message: 'Checked out successfully', checkOut: updated.checkOut, mealsServed: updated.mealsServed });
  } catch (err) {
    console.error('Check-out error:', err);
    res.status(500).json({ error: 'Failed to check out', details: err.message });
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

    // Check if donor with same name already exists for this kitchen/org
    const existingDonor = await prisma.donor.findFirst({
      where: { name, kitchenId: parseInt(kitchenId) },
    });
    if (existingDonor) {
      return res.status(409).json({ error: 'A donor with this name already exists for this organization' });
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

// Get recurring shifts for an org/category (no dayOfWeek filter)
app.get('/api/recurring-shifts', async (req, res) => {
  try {
    const { organizationId, category } = req.query;
    if (!organizationId || !category) {
      return res.status(400).json({ error: 'organizationId and category are required' });
    }
    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });
    const recShifts = await prisma.recurringShift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
      },
      orderBy: { startTime: 'asc' },
    });
    res.json(recShifts);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch recurring shifts', details: err.message });
  }
});

// ADMIN: Check in a user for a shift (by userId, date, category, organizationId, [recurringShiftId])
app.post('/api/admin/checkin', async (req, res) => {
  try {
    let { userId, date, category, organizationId, recurringShiftId } = req.body;
    if (!userId || !date || !category || !organizationId) {
      return res.status(400).json({ error: 'userId, date, category, and organizationId are required' });
    }
    let realShift = null;
    if (recurringShiftId) {
      // 1. Get the recurring shift template
      const template = await prisma.recurringShift.findUnique({ where: { id: parseInt(recurringShiftId) } });
      if (!template) return res.status(404).json({ error: 'Recurring shift not found' });
      // 2. Compute start/end time for the selected date
      const shiftStart = new Date(date + 'T' + template.startTime.toISOString().substr(11, 8));
      const shiftEnd = new Date(date + 'T' + template.endTime.toISOString().substr(11, 8));
      // 3. Look for a real shift in the Shift table
      realShift = await prisma.shift.findFirst({
        where: {
          shiftCategoryId: template.shiftCategoryId,
          organizationId: template.organizationId,
          startTime: shiftStart,
      },
    });
      // 4. If not found, create it
    if (!realShift) {
      realShift = await prisma.shift.create({
        data: {
            name: template.name,
            shiftCategoryId: template.shiftCategoryId,
          startTime: shiftStart,
          endTime: shiftEnd,
            location: template.location,
            slots: template.slots,
            organizationId: template.organizationId,
        },
      });
    }
    } else {
      // Fallback: do NOT allow check-in if no recurring shift is selected
      return res.status(400).json({ error: 'No recurring shift selected. Please select a shift template.' });
    }
    // 5. Now use realShift.id for ShiftSignup
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
    
    // Find ALL shifts for this date/category/org (using the same logic as checkin)
    const start = new Date(date + 'T00:00:00');
    const end = new Date(date + 'T23:59:59');
    
    const realShifts = await prisma.shift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
    });
    
    if (realShifts.length === 0) {
      return res.status(404).json({ error: 'No shift found for this date/category/org' });
    }
    
    // Find the signup for this user across all shifts for this date/category/org
    let signup = null;
    for (const shift of realShifts) {
      signup = await prisma.shiftSignup.findFirst({
        where: { userId: parseInt(userId), shiftId: shift.id },
      });
      if (signup) break; // Found the signup
    }
    
    if (!signup) {
      return res.status(404).json({ error: 'No signup found for this user/shift' });
    }
    
    // Update the signup with checkout time
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
    // Find all real shifts for that date/category/org (using same logic as checkout)
    const start = new Date(date + 'T00:00:00');
    const end = new Date(date + 'T23:59:59');
    const realShifts = await prisma.shift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
    });
    if (realShifts.length === 0) {
      // No real shift for this date/category/org
      return res.json(null);
    }
    // Find the signup for this user across all shifts for this date/category/org
    let signup = null;
    for (const shift of realShifts) {
      signup = await prisma.shiftSignup.findFirst({
        where: { userId: parseInt(userId), shiftId: shift.id },
      });
      if (signup) break; // Found the signup
    }
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

// 1. GET /api/terms-and-conditions/:organizationId/active
app.get('/api/terms-and-conditions/:organizationId/active', async (req, res) => {
  try {
    const { organizationId } = req.params;
    const terms = await prisma.termsAndConditions.findFirst({
      where: {
        organizationId: parseInt(organizationId),
        isActive: true
      },
      orderBy: { version: 'desc' }
    });
    if (!terms) return res.status(404).json({ error: 'No active terms found' });
    res.json(terms);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch terms', details: err.message });
  }
});

// 2. GET /api/admin/meals-count-entries
app.get('/api/admin/meals-count-entries', async (req, res) => {
  try {
    const { userId, date, organizationId } = req.query;
    if (!userId || !date || !organizationId) return res.status(400).json({ error: 'userId, date, and organizationId are required' });
    const start = new Date(date + 'T00:00:00Z');
    const end = new Date(date + 'T23:59:59Z');
    const entries = await prisma.shiftSignup.findMany({
      where: {
        userId: parseInt(userId),
        shift: {
          organizationId: parseInt(organizationId),
          startTime: { gte: start, lte: end },
        },
      },
      include: {
        shift: {
          include: {
            shiftCategory: true,
          },
        },
      },
      orderBy: { id: 'asc' },
    });
    res.json(entries);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch meals count entries', details: err.message });
  }
});

// 3. PATCH /api/admin/meals-count-entry/:id
app.patch('/api/admin/meals-count-entry/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { mealsServed } = req.body;
    if (!mealsServed || isNaN(mealsServed)) return res.status(400).json({ error: 'mealsServed is required and must be a number' });
    const updated = await prisma.shiftSignup.update({
      where: { id: parseInt(id) },
      data: { mealsServed: parseInt(mealsServed) },
    });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update meals count entry', details: err.message });
  }
});

// 4. DELETE /api/admin/meals-count-entry/:id
app.delete('/api/admin/meals-count-entry/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.shiftSignup.delete({ where: { id: parseInt(id) } });
    res.json({ message: 'Entry deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete meals count entry', details: err.message });
  }
});

// Get volunteer history (completed shifts only)
app.get('/api/volunteer-history', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ error: 'userId is required' });
    // Find all signups for this user, include shift, category, org
    const signups = await prisma.shiftSignup.findMany({
      where: { 
        userId: parseInt(userId),
        checkOut: { not: null } // Only completed shifts
      },
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
    // Filter out Collection and Meals Counting categories
    const filtered = signups.filter(s =>
      s.shift.shiftCategory.name !== 'Collection' &&
      s.shift.shiftCategory.name !== 'Meals Counting'
    );
    // Map to a simpler format for frontend
    const result = filtered.map(s => ({
      signupId: s.id,
      shiftId: s.shift.id,
      name: s.shift.name,
      date: s.shift.startTime,
      time: `${formatTimeNoTZ(s.shift.startTime)}–${formatTimeNoTZ(s.shift.endTime)}`,
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
    res.status(500).json({ error: 'Failed to fetch volunteer history', details: err.message });
  }
});

// Get shifts available for meals counting (including recurring and other categories)
app.get('/api/shifts-for-meals', async (req, res) => {
  try {
    const { date, organizationId, userId } = req.query;
    if (!date || !organizationId) {
      return res.status(400).json({ error: 'date and organizationId are required' });
    }

    // Find shifts for the specified date (all categories, not just Meals Counting)
    const start = new Date(date + 'T00:00:00');
    const end = new Date(date + 'T23:59:59');
    
    // Get real shifts for this date
    const realShifts = await prisma.shift.findMany({
      where: {
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
      include: {
        shiftCategory: true,
        organization: true,
        shiftSignups: {
          where: { userId: parseInt(userId || '0') },
        },
      },
      orderBy: { startTime: 'asc' },
    });

    // Get recurring shift templates
    const dayOfWeek = start.getDay();
    const recurringTemplates = await prisma.recurringShift.findMany({
      where: {
        organizationId: parseInt(organizationId),
        dayOfWeek,
      },
      include: {
        shiftCategory: true,
        organization: true,
      },
    });

    // Create virtual shifts from recurring templates
    const virtualShifts = [];
    for (const template of recurringTemplates) {
      // Check if a real shift already exists for this date/template
      const existingRealShift = realShifts.find(shift => 
        shift.name === template.name &&
        shift.shiftCategoryId === template.shiftCategoryId &&
        shift.organizationId === template.organizationId
      );

      if (!existingRealShift) {
        const templateStart = DateTime.fromJSDate(template.startTime, { zone: 'America/Halifax' });
        const templateEnd = DateTime.fromJSDate(template.endTime, { zone: 'America/Halifax' });
        
        const halifaxDate = DateTime.fromISO(date, { zone: 'America/Halifax' });
        const virtualStart = halifaxDate.set({
          hour: templateStart.hour,
          minute: templateStart.minute,
          second: 0,
          millisecond: 0
        });
        const virtualEnd = halifaxDate.set({
          hour: templateEnd.hour,
          minute: templateEnd.minute,
          second: 0,
          millisecond: 0
        });

        virtualShifts.push({
          id: `recurring-${template.id}-${date}`,
          name: template.name,
          shiftCategoryId: template.shiftCategoryId,
          startTime: virtualStart.toUTC().toISO(),
          endTime: virtualEnd.toUTC().toISO(),
          location: template.location,
          slots: template.slots,
          category: {
            id: template.shiftCategory.id,
            name: template.shiftCategory.name,
            icon: template.shiftCategory.icon,
          },
          existingSignup: null,
          isRecurring: true,
        });
      }
    }

    // Map real shifts to frontend format
    const mappedRealShifts = realShifts.map(shift => ({
      id: shift.id,
      name: shift.name,
      shiftCategoryId: shift.shiftCategoryId,
      startTime: shift.startTime.toISOString(),
      endTime: shift.endTime.toISOString(),
      location: shift.location,
      slots: shift.slots,
      category: {
        id: shift.shiftCategory.id,
        name: shift.shiftCategory.name,
        icon: shift.shiftCategory.icon,
      },
      existingSignup: shift.shiftSignups.length > 0 ? shift.shiftSignups[0] : null,
      isRecurring: false,
    }));

    const result = [...mappedRealShifts, ...virtualShifts];
    res.json(result);
  } catch (err) {
    console.error('Error fetching shifts for meals:', err);
    res.status(500).json({ error: 'Failed to fetch shifts for meals', details: err.message });
  }
});

// Create meals counting shift and signup
app.post('/api/admin/meals-count/create-shift', async (req, res) => {
  try {
    const { userId, date, organizationId, mealsServed, mealType } = req.body;
    if (!userId || !date || !organizationId || !mealsServed || !mealType) {
      return res.status(400).json({ error: 'userId, date, organizationId, mealsServed, and mealType are required' });
    }

    // Find or create 'Meals Counting' shift category
    let mealsCategory = await prisma.shiftCategory.findFirst({
      where: { name: 'Meals Counting', organizationId: parseInt(organizationId) },
    });

    if (!mealsCategory) {
      mealsCategory = await prisma.shiftCategory.create({
        data: {
          name: 'Meals Counting',
          icon: '🍽️',
          organizationId: parseInt(organizationId),
        },
      });
    }

    // Create shift name based on meal type
    const shiftName = mealType; // Breakfast, Lunch, or Supper

    // Create the shift for the specified date
    const halifaxDate = DateTime.fromISO(date, { zone: 'America/Halifax' });
    const shiftStart = halifaxDate.set({ hour: 0, minute: 0, second: 0, millisecond: 0 });
    const shiftEnd = halifaxDate.set({ hour: 23, minute: 59, second: 59, millisecond: 999 });

    const shift = await prisma.shift.create({
      data: {
        name: shiftName,
        shiftCategoryId: mealsCategory.id,
        startTime: shiftStart.toUTC().toJSDate(),
        endTime: shiftEnd.toUTC().toJSDate(),
        location: 'Kitchen',
        slots: 1,
        organizationId: parseInt(organizationId),
      },
    });

    // Create the signup with meals count
    const signup = await prisma.shiftSignup.create({
      data: {
        userId: parseInt(userId),
        shiftId: shift.id,
        mealsServed: parseInt(mealsServed),
        // No checkIn or checkOut times for meals counting
      },
    });

    res.json({ message: 'Meals counting shift created successfully', shift, signup });
  } catch (err) {
    console.error('Error creating meals counting shift:', err);
    res.status(500).json({ error: 'Failed to create meals counting shift', details: err.message });
  }
});

// Update meals count for existing signup
app.patch('/api/shift-signups/:id/meals', async (req, res) => {
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

    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update meals count', details: err.message });
  }
});

// Create new shift signup with meals count
app.post('/api/shift-signups', async (req, res) => {
  try {
    const { userId, shiftId, mealsServed, date } = req.body;
    
    if (!userId || !shiftId) {
      return res.status(400).json({ error: 'userId and shiftId are required' });
    }

    let realShiftId = shiftId;
    let realShift = null;

    // Handle recurring shift registration
    if (typeof shiftId === 'string' && shiftId.startsWith('recurring-')) {
      const parts = shiftId.split('-');
      const recurringId = parseInt(parts[1]);
      const shiftDate = date || (parts.length > 2 ? parts[2] : null);
      
      if (!recurringId || !shiftDate) {
        return res.status(400).json({ error: 'Invalid recurring shift id or date' });
      }
      
      // Find the recurring template
      const template = await prisma.recurringShift.findUnique({ 
        where: { id: recurringId } 
      });
      
      if (!template) {
        return res.status(404).json({ error: 'Recurring shift template not found' });
      }

      // Create start and end times for the specific date
      const templateStart = DateTime.fromJSDate(template.startTime, { zone: 'America/Halifax' });
      const templateEnd = DateTime.fromJSDate(template.endTime, { zone: 'America/Halifax' });
      
      const halifaxDate = DateTime.fromISO(shiftDate, { zone: 'America/Halifax' });
      const shiftStart = halifaxDate.set({
        hour: templateStart.hour,
        minute: templateStart.minute,
        second: 0,
        millisecond: 0
      });
      const shiftEnd = halifaxDate.set({
        hour: templateEnd.hour,
        minute: templateEnd.minute,
        second: 0,
        millisecond: 0
      });

      // Check if a real shift already exists for this date/template
      realShift = await prisma.shift.findFirst({
        where: {
          name: template.name,
          shiftCategoryId: template.shiftCategoryId,
          organizationId: template.organizationId,
          startTime: shiftStart.toUTC().toJSDate(),
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
            startTime: shiftStart.toUTC().toJSDate(),
            endTime: shiftEnd.toUTC().toJSDate(),
            location: template.location,
            slots: template.slots,
            organizationId: template.organizationId,
          },
          include: {
            shiftSignups: true
          }
        });
        console.log('Created new shift from template:', realShift.id);
      }

      realShiftId = realShift.id;
    } else {
      // Handle one-off shift registration
      realShift = await prisma.shift.findUnique({
        where: { id: parseInt(shiftId) },
        include: {
          shiftSignups: true
        }
      });
      
      if (!realShift) {
        return res.status(404).json({ error: 'Shift not found' });
      }
    }

    // Check if user already has a signup for this shift
    const existingSignup = await prisma.shiftSignup.findFirst({
      where: { 
        userId: parseInt(userId), 
        shiftId: realShiftId 
      },
    });
    
    if (existingSignup) {
      return res.status(409).json({ error: 'Already signed up for this shift' });
    }

    // Create the signup
    const signupData = {
      userId: parseInt(userId),
      shiftId: realShiftId,
    };

    // Add meals count if provided
    if (mealsServed && !isNaN(mealsServed)) {
      signupData.mealsServed = parseInt(mealsServed);
    }

    const signup = await prisma.shiftSignup.create({
      data: signupData,
    });

    res.json({ message: 'Signup created successfully', signup });
  } catch (err) {
    console.error('Error creating shift signup:', err);
    res.status(500).json({ error: 'Failed to create shift signup', details: err.message });
  }
});

// Check if user has existing signup for a shift
app.get('/api/shift-signups/check', async (req, res) => {
  try {
    const { userId, shiftId } = req.query;
    if (!userId || !shiftId) {
      return res.status(400).json({ error: 'userId and shiftId are required' });
    }

    const signup = await prisma.shiftSignup.findFirst({
      where: {
        userId: parseInt(userId),
        shiftId: parseInt(shiftId),
      },
    });

    res.json({
      exists: !!signup,
      signup: signup,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check signup', details: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Server accessible at:`);
  console.log(`- http://localhost:${PORT}`);
  console.log(`- http://127.0.0.1:${PORT}`);
  console.log(`- http://172.20.10.2:${PORT}`);  // Your computer's IP
}); 