const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('./generated/prisma');
const CloudflareR2Service = require('./services/CloudflareR2Service');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const { PDFDocument: PDFLib, rgb } = require('pdf-lib');
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
    termsAndConditionsId, // For backward compatibility
    termsAndConditionsIds, // New field for multiple documents
    signature, // For backward compatibility
    signatures // New field for multiple signatures
  } = req.body;

  // Support both single and multiple terms IDs
  const termsIds = termsAndConditionsIds || [termsAndConditionsId];
  
  // Support both single signature and multiple signatures
  let signatureMap = new Map();
  if (signatures && Array.isArray(signatures)) {
    // New format: multiple signatures
    signatures.forEach(sig => {
      if (sig.termsId && sig.signature) {
        signatureMap.set(sig.termsId, sig.signature);
      }
    });
  } else if (signature) {
    // Backward compatibility: single signature for all documents
    termsIds.forEach(termId => {
      signatureMap.set(termId, signature);
    });
  }
  
  if (!firstName || !lastName || !email || !password || !organizationId || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (!termsIds || termsIds.length === 0) {
    return res.status(400).json({ error: 'At least one terms and conditions must be accepted' });
  }

  if (signatureMap.size === 0) {
    return res.status(400).json({ error: 'At least one signature must be provided' });
  }

  try {
    // Check if all terms and conditions exist
    const terms = await prisma.termsAndConditions.findMany({
      where: { 
        id: { in: termsIds },
        organizationId: organizationId
      }
    });

    if (terms.length !== termsIds.length) {
      return res.status(400).json({ error: 'One or more terms and conditions are invalid' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with PENDING status and new fields
    const user = await prisma.user.create({
      data: { 
        email, 
        phone, 
        password: hashedPassword, 
        firstName, 
        lastName, 
        organizationId, 
        role,
        status: 'PENDING',
        // NEW FIELDS - ALL OPTIONAL
        registrationType: req.body.registrationType,
        ageBracket: req.body.ageBracket,
        birthdate: req.body.birthdate ? new Date(req.body.birthdate) : null,
        pronouns: req.body.pronouns,
        address: req.body.address,
        city: req.body.city,
        postalCode: req.body.postalCode,
        homePhone: req.body.homePhone,
        emergencyContactName: req.body.emergencyContactName,
        emergencyContactNumber: req.body.emergencyContactNumber,
        communicationPreferences: req.body.communicationPreferences ? JSON.stringify(req.body.communicationPreferences) : null,
        profilePictureUrl: req.body.profilePictureUrl,
        allergies: req.body.allergies,
        medicalConcerns: req.body.medicalConcerns,
        preferredDays: req.body.preferredDays ? JSON.stringify(req.body.preferredDays) : null,
        preferredShifts: req.body.preferredShifts ? JSON.stringify(req.body.preferredShifts) : null,
        frequency: req.body.frequency,
        preferredPrograms: req.body.preferredPrograms ? JSON.stringify(req.body.preferredPrograms) : null,
        canCallIfShortHanded: req.body.canCallIfShortHanded,
        schoolWorkCommitment: req.body.schoolWorkCommitment,
        requiredHours: req.body.requiredHours ? parseInt(req.body.requiredHours) : null,
        howDidYouHear: req.body.howDidYouHear,
        startDate: req.body.startDate ? new Date(req.body.startDate) : null,
        parentGuardianName: req.body.parentGuardianName,
        parentGuardianEmail: req.body.parentGuardianEmail,
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

    // Process each document and append signatures to original PDFs
    let signedDocumentUrls = [];
    try {
      console.log(`Starting PDF processing for ${terms.length} documents`);
      console.log(`Terms data:`, terms);
      console.log(`Signature map:`, signatureMap);
      
      for (const term of terms) {
        const termSignature = signatureMap.get(term.id);
        if (!termSignature) {
          console.warn(`No signature found for terms ID: ${term.id}`);
          continue;
        }

        console.log(`Processing document ${term.id}: ${term.title}`);
        console.log(`Document fileUrl: ${term.fileUrl}`);
        console.log(`Document fileName: ${term.fileName}`);

        try {
          // Download the original PDF
          console.log(`Downloading original PDF: ${term.fileUrl}`);
          const originalPdfBuffer = await CloudflareR2Service.downloadFile(term.fileUrl);
          console.log(`Downloaded PDF buffer size: ${originalPdfBuffer.byteLength} bytes`);
          
          // Load the original PDF
          console.log(`Loading PDF with pdf-lib...`);
          const pdfDoc = await PDFLib.load(originalPdfBuffer);
          console.log(`PDF loaded successfully, pages: ${pdfDoc.getPageCount()}`);
          
          // Create a new page for the signature
          const page = pdfDoc.addPage();
          const { width, height } = page.getSize();
          console.log(`Added signature page, dimensions: ${width}x${height}`);
          
          // Add signature content to the new page
          const fontSize = 12;
          const margin = 40;
          
          // Title
          page.drawText('DIGITAL SIGNATURE PAGE', {
            x: margin,
            y: height - margin,
            size: 18,
            color: rgb(0, 0, 0),
          });
          
          // User Information
          page.drawText('User Information:', {
            x: margin,
            y: height - margin - 40,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          page.drawText(`Name: ${firstName} ${lastName}`, {
            x: margin,
            y: height - margin - 60,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          page.drawText(`Email: ${email}`, {
            x: margin,
            y: height - margin - 80,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          page.drawText(`Organization: ${orgName}`, {
            x: margin,
            y: height - margin - 100,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          page.drawText(`Role: ${role}`, {
            x: margin,
            y: height - margin - 120,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          // Document Information
          page.drawText('Document Information:', {
            x: margin,
            y: height - margin - 160,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          page.drawText(`Title: ${term.title}`, {
            x: margin,
            y: height - margin - 180,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          page.drawText(`Version: ${term.version}`, {
            x: margin,
            y: height - margin - 200,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          // Digital Signature
          page.drawText('Digital Signature:', {
            x: margin,
            y: height - margin - 240,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          page.drawText(termSignature, {
            x: margin,
            y: height - margin - 260,
            size: 16,
            color: rgb(0, 0, 0),
          });
          
          // Signature Date and Metadata
          page.drawText(`Signed Date: ${new Date().toISOString()}`, {
            x: margin,
            y: height - margin - 300,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          page.drawText(`IP Address: ${req.ip || 'unknown'}`, {
            x: margin,
            y: height - margin - 320,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          // Confirmation Statement
          page.drawText('I have read and agree to the terms and conditions in this document.', {
            x: margin,
            y: height - margin - 360,
            size: fontSize,
            color: rgb(0, 0, 0),
          });
          
          // Save the modified PDF
          console.log(`Saving modified PDF...`);
          const modifiedPdfBytes = await pdfDoc.save();
          console.log(`Modified PDF saved, size: ${modifiedPdfBytes.length} bytes`);
          
          // Upload the signed original document with predictable filename
          const originalFileName = term.fileName || `document-${term.id}.pdf`;
          const signedFileName = `signed-document-${term.id}-${originalFileName}`;
          console.log(`Uploading to R2 with filename: ${signedFileName}`);
          
          const uploadResult = await CloudflareR2Service.uploadSignedOriginalDocument(
            Buffer.from(modifiedPdfBytes),
            signedFileName,
            user.id.toString(),
            organizationId.toString()
          );
          
          signedDocumentUrls.push(uploadResult.url);
          console.log(`✅ Signed original document uploaded for term ${term.id}: ${uploadResult.url}`);
          console.log(`Filename: ${signedFileName}`);
          
        } catch (docError) {
          console.error(`❌ Failed to process document ${term.id}:`, docError);
          console.error(`Error stack:`, docError.stack);
          // Continue with other documents
        }
      }
      
      console.log(`Successfully processed ${signedDocumentUrls.length} documents`);
    } catch (pdfErr) {
      console.error('❌ Failed to process signed documents:', pdfErr);
      console.error('Error stack:', pdfErr.stack);
      // Continue without the signed document URLs
    }

    // Create user agreement records for all accepted terms
    for (const termId of termsIds) {
      const termSignature = signatureMap.get(termId);
      if (!termSignature) {
        console.warn(`No signature found for terms ID: ${termId}`);
        continue;
      }
      
      // Find the corresponding signed document URL
      const term = terms.find(t => t.id === termId);
      console.log(`Looking for signed document URL for term ID: ${termId}`);
      console.log(`Available signed document URLs:`, signedDocumentUrls);
      
      // Improved URL matching logic
      let signedDocumentUrl = null;
      if (signedDocumentUrls.length > 0) {
        // Try to find URL by term ID in the filename
        signedDocumentUrl = signedDocumentUrls.find(url => {
          const fileName = url.split('/').pop(); // Get filename from URL
          console.log(`Checking URL: ${url}, filename: ${fileName}`);
          
          // Check if filename contains the term ID in the new format
          if (fileName.includes(`signed-document-${termId}-`)) {
            console.log(`Found matching URL for term ${termId}: ${url}`);
            return true;
          }
          
          // Fallback: Check if filename contains the term ID
          if (fileName.includes(`document-${termId}`) || fileName.includes(`-${termId}.pdf`)) {
            console.log(`Found matching URL for term ${termId}: ${url}`);
            return true;
          }
          
          // Fallback: Check if filename contains the original filename
          if (term?.fileName && fileName.includes(term.fileName)) {
            console.log(`Found matching URL by original filename for term ${termId}: ${url}`);
            return true;
          }
          
          return false;
        });
      }
      
      if (!signedDocumentUrl) {
        console.warn(`No signed document URL found for term ID: ${termId}`);
        // If no specific URL found, use the first available URL as fallback
        if (signedDocumentUrls.length > 0) {
          signedDocumentUrl = signedDocumentUrls[0];
          console.log(`Using fallback URL for term ${termId}: ${signedDocumentUrl}`);
        }
      }
      
      console.log(`Creating user agreement for term ${termId} with URL: ${signedDocumentUrl}`);
      
      await prisma.userAgreement.create({
        data: {
          userId: user.id,
          organizationId: organizationId,
          termsAndConditionsId: termId,
          signature: termSignature,
          signedDocumentUrl: signedDocumentUrl,
          ipAddress: req.ip || 'unknown',
          userAgent: req.get('User-Agent') || 'unknown',
        },
      });
    }

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
    if (signedDocumentUrls.length > 0) {
      console.log(`Signed documents uploaded: ${signedDocumentUrls.length} documents`);
      signedDocumentUrls.forEach((url, index) => {
        console.log(`  Document ${index + 1}: ${url}`);
      });
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
      signedDocumentUrls: signedDocumentUrls
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

// Delete user account endpoint
app.delete('/api/users/:id', async (req, res) => {
  const userId = parseInt(req.params.id);
  const { password } = req.body;
  
  if (isNaN(userId) || !password) {
    return res.status(400).json({ error: 'Valid user ID and password are required' });
  }

  try {
    // Get the current user to verify password
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Password is incorrect' });
    }

    // Delete user account and all related data
    // We need to delete related records manually due to foreign key constraints
    
    try {
      // Start a transaction to ensure all deletions succeed or fail together
      await prisma.$transaction(async (tx) => {
        console.log(`Starting deletion process for user ${userId}`);
        
        // First, update any users who reference this user as approvedBy or deniedBy
        const approvedByUpdate = await tx.user.updateMany({
          where: { approvedBy: userId },
          data: { approvedBy: null }
        });
        console.log(`Updated ${approvedByUpdate.count} users who referenced this user as approvedBy`);
        
        const deniedByUpdate = await tx.user.updateMany({
          where: { deniedBy: userId },
          data: { deniedBy: null }
        });
        console.log(`Updated ${deniedByUpdate.count} users who referenced this user as deniedBy`);
        
        // Delete user agreements
        console.log(`Attempting to delete user agreements for user ${userId}`);
        const agreementsDeleted = await tx.userAgreement.deleteMany({
          where: { userId: userId },
        });
        console.log(`Deleted ${agreementsDeleted.count} user agreements`);
        
        // Delete module permissions
        const permissionsDeleted = await tx.userModulePermission.deleteMany({
          where: { userId: userId },
        });
        console.log(`Deleted ${permissionsDeleted.count} module permissions`);
        
        // Delete shift signups (this will cascade to donations)
        const shiftSignupsDeleted = await tx.shiftSignup.deleteMany({
          where: { userId: userId },
        });
        console.log(`Deleted ${shiftSignupsDeleted.count} shift signups`);
        
        // Verify all related records are deleted before deleting the user
        const remainingAgreements = await tx.userAgreement.count({ where: { userId: userId } });
        const remainingPermissions = await tx.userModulePermission.count({ where: { userId: userId } });
        const remainingShiftSignups = await tx.shiftSignup.count({ where: { userId: userId } });
        
        if (remainingAgreements > 0 || remainingPermissions > 0 || remainingShiftSignups > 0) {
          throw new Error(`Failed to delete all related records. Remaining: ${remainingAgreements} agreements, ${remainingPermissions} permissions, ${remainingShiftSignups} shift signups`);
        }
        
        // Finally delete the user
        await tx.user.delete({
          where: { id: userId },
        });
        console.log(`Successfully deleted user ${userId}`);
      });
    } catch (transactionError) {
      console.error('Transaction failed during user deletion:', transactionError);
      
      // Check for specific Prisma error codes
      if (transactionError.code === 'P2003') {
        throw new Error('Cannot delete account due to existing data relationships. Please contact support.');
      } else if (transactionError.code === 'P2025') {
        throw new Error('User not found or already deleted');
      } else if (transactionError.code === 'P2002') {
        throw new Error('Database constraint violation during deletion');
      } else {
        throw new Error(`Failed to delete user account: ${transactionError.message}`);
      }
    }

    res.json({ message: 'User account deleted successfully' });
  } catch (err) {
    console.error('Error deleting user account:', err);
    
    // Provide more user-friendly error messages
    let errorMessage = 'Failed to delete user account';
    if (err.code === 'P2003') {
      errorMessage = 'Cannot delete account due to existing data relationships. Please contact support.';
    } else if (err.code === 'P2025') {
      errorMessage = 'User not found or already deleted';
    } else if (err.message) {
      errorMessage = err.message;
    }
    
    res.status(500).json({ error: errorMessage, details: err.message });
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

    // Fetch ALL real shifts in the date range (including inactive ones)
    // We need to see ALL shifts to know which dates are "blocked" by inactive shifts
    const allRealShifts = await prisma.shift.findMany({
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
        RecurringShift: true, // Include to check recurring shift status
      },
      orderBy: { startTime: 'asc' },
    });

    console.log('Found all real shifts (including inactive):', allRealShifts.length);

    // Filter shifts based on isActive status
    const realShifts = allRealShifts.filter(shift => {
      // If this shift has a recurringShiftId, check both Shift.isActive AND RecurringShift.isActive
      if (shift.recurringShiftId && shift.RecurringShift) {
        return shift.isActive && shift.RecurringShift.isActive;
      }
      // If no recurringShiftId, just check Shift.isActive
      return shift.isActive;
    });

    console.log('After isActive filter:', realShifts.length);

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
        isRecurring: shift.recurringShiftId ? true : false,
        date: halifaxStart.toISODate(),
      };
    });

    // Fetch recurring shift templates (only active ones)
    const recurringTemplates = await prisma.recurringShift.findMany({
      where: {
        organizationId: parseInt(organizationId),
        isActive: true, // Only show active recurring shift templates
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
      // Convert Luxon weekday to DB format
      // Luxon: 1=Monday, 2=Tuesday, 3=Wednesday, 4=Thursday, 5=Friday, 6=Saturday, 7=Sunday
      // DB: 0=Sunday, 1=Monday, 2=Tuesday, 3=Wednesday, 4=Thursday, 5=Friday, 6=Saturday
      const dayOfWeek = date.weekday === 7 ? 0 : date.weekday;
      console.log(`Luxon weekday: ${date.weekday}, Converted dayOfWeek: ${dayOfWeek}`);
      console.log(`\n=== VIRTUAL SHIFT GENERATION for ${date.toISODate()} ===`);
      console.log(`Date: ${date.toISODate()}, Day of week: ${dayOfWeek} (0=Sunday, 1=Monday, etc.)`);
      console.log(`Total recurring templates: ${recurringTemplates.length}`);
      
      // Log all recurring templates and their dayOfWeek
      recurringTemplates.forEach((template, index) => {
        console.log(`  Template ${index + 1}: "${template.name}" - dayOfWeek: ${template.dayOfWeek} - isActive: ${template.isActive}`);
      });
      
      for (const template of recurringTemplates) {
        console.log(`\nChecking template: "${template.name}" (dayOfWeek: ${template.dayOfWeek})`);
        if (template.dayOfWeek === dayOfWeek) {
          console.log(`  ✅ Day of week matches! Creating virtual shift...`);
            // Check if a real shift already exists for this date/template (including inactive ones)
            // We need to check ALL shifts to know if a date is "blocked" by an inactive shift
            const existingRealShift = allRealShifts.find(shift => 
              shift.name === template.name &&
              shift.shiftCategoryId === template.shiftCategoryId &&
              shift.organizationId === template.organizationId
            );

            // Debug logging
            if (existingRealShift) {
              console.log(`Found existing real shift for ${template.name} on ${date.toISODate()}:`, {
                shiftId: existingRealShift.id,
                isActive: existingRealShift.isActive,
                recurringShiftId: existingRealShift.recurringShiftId
              });
            }

            // Only create virtual shift if NO real shift exists for this date/template
            // If a real shift exists (active or inactive), don't create virtual shift
            if (!existingRealShift) {
              console.log(`Creating virtual shift for ${template.name} on ${date.toISODate()} - no real shift exists`);
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
            } else {
              console.log(`Skipping virtual shift for ${template.name} on ${date.toISODate()} - real shift exists (ID: ${existingRealShift.id}, Active: ${existingRealShift.isActive})`);
            }
        } else {
          console.log(`  ❌ Day of week doesn't match (template: ${template.dayOfWeek}, date: ${dayOfWeek})`);
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
            recurringShiftId: template.id, // Link to the recurring template
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
    const result = filtered.map(s => {
      // Convert UTC times to Halifax timezone
      const halifaxStart = DateTime.fromJSDate(s.shift.startTime, { zone: 'America/Halifax' });
      const halifaxEnd = DateTime.fromJSDate(s.shift.endTime, { zone: 'America/Halifax' });
      
      return {
      signupId: s.id,
      shiftId: s.shift.id,
      name: s.shift.name,
      date: s.shift.startTime,
        time: `${halifaxStart.toFormat('h:mm a')}–${halifaxEnd.toFormat('h:mm a')}`,
      location: s.shift.organization.name,
      slots: s.shift.slots,
      icon: getShiftIcon(s.shift.shiftCategory.name, s.shift.name),
      category: s.shift.shiftCategory.name,
      checkIn: s.checkIn,
      checkOut: s.checkOut,
      mealsServed: s.mealsServed,
      organization: s.shift.organization.name,
      organizationId: s.shift.organizationId,
      };
    });
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

// ADMIN: Get users registered for shifts on a specific date and category
app.get('/api/admin/registered-users', async (req, res) => {
  try {
    const { organizationId, date, category } = req.query;
    if (!organizationId || !date || !category) {
      return res.status(400).json({ error: 'organizationId, date, and category are required' });
    }

    // Find the shiftCategoryId
    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });

    // Find all real shifts for that date/category/org
    const start = new Date(date + 'T00:00:00');
    const end = new Date(date + 'T23:59:59');
    
    const realShifts = await prisma.shift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
    });

    // Also check for recurring shift signups for this date/category
    const selectedDate = new Date(date + 'T00:00:00Z');
    const dayOfWeek = selectedDate.getUTCDay();
    
    const recurringShifts = await prisma.recurringShift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        dayOfWeek: dayOfWeek,
        isActive: true,
      },
    });

    // Get all shift IDs (both real and recurring)
    const realShiftIds = realShifts.map(shift => shift.id);
    const recurringShiftIds = recurringShifts.map(shift => shift.id);

    if (realShiftIds.length === 0) {
      return res.json([]);
    }

    // Find all users who have signups for these shifts (only real shifts, not recurring)
    // Note: ShiftSignup only has shiftId, not recurringShiftId
    console.log(`\n=== REGISTERED USERS DEBUG for ${category} on ${date} ===`);
    console.log(`- Real shift IDs:`, realShiftIds);
    console.log(`- Recurring shift IDs:`, recurringShiftIds);
    console.log(`- Only checking real shift signups (not recurring)`);
    
    const signups = await prisma.shiftSignup.findMany({
      where: {
        shiftId: { in: realShiftIds }
      },
      include: {
        user: {
          select: { id: true, firstName: true, lastName: true, email: true, role: true },
        },
      },
    });
    
    console.log(`- Found ${signups.length} signups for real shifts`);
    signups.forEach((signup, index) => {
      console.log(`  ${index + 1}. User: ${signup.user.firstName} ${signup.user.lastName} - Shift ID: ${signup.shiftId}`);
    });

    // Extract unique users from signups
    const userMap = new Map();
    signups.forEach(signup => {
      if (!userMap.has(signup.user.id)) {
        userMap.set(signup.user.id, signup.user);
      }
    });

    const users = Array.from(userMap.values()).sort((a, b) => 
      a.firstName.localeCompare(b.firstName)
    );

    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch registered users', details: err.message });
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
    // Fetch ALL real shifts in the date range (including inactive ones)
    const allRealShifts = await prisma.shift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
      include: {
        shiftSignups: {
          include: { user: true },
        },
        RecurringShift: true, // Include to check recurring shift status
      },
      orderBy: { startTime: 'asc' },
    });

    // Filter shifts based on isActive status
    const realShifts = allRealShifts.filter(shift => {
      // If this shift has a recurringShiftId, check both Shift.isActive AND RecurringShift.isActive
      if (shift.recurringShiftId && shift.RecurringShift) {
        return shift.isActive && shift.RecurringShift.isActive;
      }
      // If no recurringShiftId, just check Shift.isActive
      return shift.isActive;
    });
    // Find recurring templates for this category/org
    const dayOfWeek = start.getUTCDay();
    const recurringTemplates = await prisma.recurringShift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        dayOfWeek,
        isActive: true, // Only show active recurring shifts
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
      isRecurring: shift.recurringShiftId ? true : false,
      date: shift.startTime.toISOString().slice(0, 10),
      shiftSignups: shift.shiftSignups,
    }));
    res.json([...mappedShifts, ...virtualShifts]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admin shifts', details: err.message });
  }
});

// Get recurring shifts for an org/category with optional dayOfWeek filter
app.get('/api/recurring-shifts', async (req, res) => {
  try {
    const { organizationId, category, dayOfWeek } = req.query;
    if (!organizationId || !category) {
      return res.status(400).json({ error: 'organizationId and category are required' });
    }
    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });
    
    // Build where clause
    const whereClause = {
      shiftCategoryId: shiftCategory.id,
      organizationId: parseInt(organizationId),
    };
    
    // Add dayOfWeek filter if provided
    if (dayOfWeek !== undefined) {
      whereClause.dayOfWeek = parseInt(dayOfWeek);
    }
    
    const recShifts = await prisma.recurringShift.findMany({
      where: {
        ...whereClause,
        isActive: true, // Only show active recurring shifts
      },
      orderBy: { startTime: 'asc' },
    });
    res.json(recShifts);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch recurring shifts', details: err.message });
  }
});

// Get available shifts for admin check-in/out (combines real and recurring shifts intelligently)
app.get('/api/admin/available-shifts', async (req, res) => {
  try {
    const { organizationId, category, date } = req.query;
    if (!organizationId || !category || !date) {
      return res.status(400).json({ error: 'organizationId, category, and date are required' });
    }

    const shiftCategory = await prisma.shiftCategory.findFirst({
      where: { name: category, organizationId: parseInt(organizationId) },
    });
    if (!shiftCategory) return res.status(404).json({ error: 'Category not found' });

    // Get the day of week for the selected date (0 = Sunday, 1 = Monday, etc.)
    const selectedDate = new Date(date + 'T00:00:00Z');
    const dayOfWeek = selectedDate.getUTCDay();

    // Find all real shifts for the selected date
    const start = new Date(date + 'T00:00:00Z');
    const end = new Date(date + 'T23:59:59Z');
    
    // Fetch ALL real shifts in the date range (including inactive ones)
    const allRealShifts = await prisma.shift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        startTime: { gte: start, lte: end },
      },
      include: {
        RecurringShift: true, // Include to check recurring shift status
      },
      orderBy: { startTime: 'asc' },
    });

    // Filter shifts based on isActive status
    const realShifts = allRealShifts.filter(shift => {
      // If this shift has a recurringShiftId, check both Shift.isActive AND RecurringShift.isActive
      if (shift.recurringShiftId && shift.RecurringShift) {
        return shift.isActive && shift.RecurringShift.isActive;
      }
      // If no recurringShiftId, just check Shift.isActive
      return shift.isActive;
    });

    // Find all recurring shifts for the day of week (including those with null dayOfWeek)
    const recurringShifts = await prisma.recurringShift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        OR: [
          { dayOfWeek: dayOfWeek },
          { dayOfWeek: null } // Include shifts that don't have dayOfWeek set
        ],
        isActive: true, // Only show active recurring shifts
      },
      orderBy: { startTime: 'asc' },
    });

    // For non-recurring shifts (dayOfWeek = null), we need to check if they have real shifts for the specific date
    const nonRecurringShifts = recurringShifts.filter(shift => shift.dayOfWeek === null);
    const recurringShiftsForDay = recurringShifts.filter(shift => shift.dayOfWeek === dayOfWeek);
    
    console.log(`- Found ${recurringShiftsForDay.length} recurring shifts for day ${dayOfWeek}`);
    console.log(`- Found ${nonRecurringShifts.length} non-recurring shifts (dayOfWeek = null)`);

    console.log(`\n=== AVAILABLE SHIFTS DEBUG for ${category} on ${date} ===`);
    console.log(`- Day of week: ${dayOfWeek} (0=Sunday, 1=Monday, etc.)`);
    console.log(`- Found ${allRealShifts.length} total real shifts in database`);
    console.log(`- Found ${realShifts.length} active real shifts after filtering`);
    console.log(`- Found ${recurringShifts.length} active recurring shifts`);
    
    // Debug: Check all recurring shifts for this category (regardless of dayOfWeek)
    const allRecurringShifts = await prisma.recurringShift.findMany({
      where: {
        shiftCategoryId: shiftCategory.id,
        organizationId: parseInt(organizationId),
        isActive: true,
      },
    });
    console.log(`- Total recurring shifts for category: ${allRecurringShifts.length}`);
    allRecurringShifts.forEach((shift, index) => {
      console.log(`  ${index + 1}. "${shift.name}" - dayOfWeek: ${shift.dayOfWeek} - isActive: ${shift.isActive}`);
    });
    
    console.log('\n=== ALL REAL SHIFTS IN DATABASE ===');
    allRealShifts.forEach((shift, index) => {
      console.log(`  ${index + 1}. Real shift: "${shift.name}" (${shift.startTime.toISOString()} - ${shift.endTime.toISOString()}) [ID: ${shift.id}] [RecurringID: ${shift.recurringShiftId}] [Active: ${shift.isActive}]`);
    });
    
    console.log('\n=== ACTIVE REAL SHIFTS ===');
    realShifts.forEach((shift, index) => {
      console.log(`  ${index + 1}. Active real shift: "${shift.name}" (${shift.startTime.toISOString()} - ${shift.endTime.toISOString()}) [ID: ${shift.id}] [RecurringID: ${shift.recurringShiftId}]`);
    });
    
    console.log('\n=== RECURRING SHIFTS ===');
    recurringShifts.forEach((shift, index) => {
      console.log(`  ${index + 1}. Recurring shift: "${shift.name}" (${shift.startTime.toISOString()} - ${shift.endTime.toISOString()}) [ID: ${shift.id}]`);
    });

    // Build available shifts list - prioritize real shifts over recurring templates
    const availableShifts = [];
    const processedShiftKeys = new Set();

    console.log('\n=== PROCESSING REAL SHIFTS ===');
    // First, add all real shifts for the selected date (with duplicate prevention)
    realShifts.forEach((realShift, index) => {
      // Create a more robust unique key based on name, rounded start time, and end time to avoid duplicates
      // Round times to the nearest minute to handle timezone/precision differences
      const startTimeRounded = new Date(Math.round(realShift.startTime.getTime() / 60000) * 60000);
      const endTimeRounded = new Date(Math.round(realShift.endTime.getTime() / 60000) * 60000);
      const shiftKey = `${realShift.name}-${startTimeRounded.toISOString()}-${endTimeRounded.toISOString()}`;
      
      console.log(`\nProcessing real shift ${index + 1}:`);
      console.log(`  Name: "${realShift.name}"`);
      console.log(`  Time: ${realShift.startTime.toISOString()} - ${realShift.endTime.toISOString()}`);
      console.log(`  Rounded Time: ${startTimeRounded.toISOString()} - ${endTimeRounded.toISOString()}`);
      console.log(`  ID: ${realShift.id}`);
      console.log(`  RecurringID: ${realShift.recurringShiftId}`);
      console.log(`  Shift Key: "${shiftKey}"`);
      console.log(`  Already processed: ${processedShiftKeys.has(shiftKey)}`);
      
      // Only add if we haven't seen this exact shift before
      // But be more lenient - only skip if it's the exact same shift ID
      const existingShift = availableShifts.find(s => s.id === realShift.id);
      if (!existingShift) {
        availableShifts.push({
          id: realShift.id,
          name: realShift.name,
          startTime: realShift.startTime,
          endTime: realShift.endTime,
          location: realShift.location,
          slots: realShift.slots,
          isReal: true,
          isRecurring: realShift.recurringShiftId ? true : false,
        });
        processedShiftKeys.add(shiftKey);
        console.log(`  ✅ ADDED real shift: ${realShift.name} [ID: ${realShift.id}]`);
      } else {
        console.log(`  ❌ SKIPPED duplicate real shift: ${realShift.name} [ID: ${realShift.id}] - Already exists`);
      }
    });

    console.log('\n=== PROCESSING RECURRING SHIFTS FOR DAY ===');
    // Process recurring shifts for the specific day of week
    recurringShiftsForDay.forEach((recurringShift, index) => {
      console.log(`\nProcessing recurring shift ${index + 1}:`);
      console.log(`  Name: "${recurringShift.name}"`);
      console.log(`  Time: ${recurringShift.startTime.toISOString()} - ${recurringShift.endTime.toISOString()}`);
      console.log(`  ID: ${recurringShift.id}`);
      console.log(`  DayOfWeek: ${recurringShift.dayOfWeek}`);
      
      // Check if there's already a real shift created from this recurring shift template
      const hasRealShiftFromTemplate = realShifts.some(realShift => 
        realShift.recurringShiftId === recurringShift.id
      );
      console.log(`  Has real shift from template: ${hasRealShiftFromTemplate}`);
      
      if (!hasRealShiftFromTemplate) {
        availableShifts.push({
          id: recurringShift.id,
          name: recurringShift.name,
          startTime: recurringShift.startTime,
          endTime: recurringShift.endTime,
          location: recurringShift.location,
          slots: recurringShift.slots,
          isReal: false,
          isRecurring: true,
        });
        console.log(`  ✅ ADDED recurring shift: ${recurringShift.name} [ID: ${recurringShift.id}]`);
      } else {
        console.log(`  ❌ SKIPPED recurring shift (has real shift): ${recurringShift.name} [ID: ${recurringShift.id}]`);
      }
    });

    console.log('\n=== PROCESSING NON-RECURRING SHIFTS (dayOfWeek = null) ===');
    // Process non-recurring shifts - these should only show if they have real shifts for the specific date
    nonRecurringShifts.forEach((nonRecurringShift, index) => {
      console.log(`\nProcessing non-recurring shift ${index + 1}:`);
      console.log(`  Name: "${nonRecurringShift.name}"`);
      console.log(`  Time: ${nonRecurringShift.startTime.toISOString()} - ${nonRecurringShift.endTime.toISOString()}`);
      console.log(`  ID: ${nonRecurringShift.id}`);
      console.log(`  DayOfWeek: ${nonRecurringShift.dayOfWeek} (null = non-recurring)`);
      
      // For non-recurring shifts, check if there's a real shift for the specific date
      const hasRealShiftForDate = realShifts.some(realShift => 
        realShift.recurringShiftId === nonRecurringShift.id
      );
      console.log(`  Has real shift for this date: ${hasRealShiftForDate}`);
      
      if (hasRealShiftForDate) {
        // Find the real shift for this date
        const realShiftForDate = realShifts.find(realShift => 
          realShift.recurringShiftId === nonRecurringShift.id
        );
        
        if (realShiftForDate) {
          availableShifts.push({
            id: realShiftForDate.id,
            name: realShiftForDate.name,
            startTime: realShiftForDate.startTime,
            endTime: realShiftForDate.endTime,
            location: realShiftForDate.location,
            slots: realShiftForDate.slots,
            isReal: true,
            isRecurring: true,
          });
          console.log(`  ✅ ADDED real shift for non-recurring: ${realShiftForDate.name} [ID: ${realShiftForDate.id}]`);
        }
      } else {
        console.log(`  ❌ SKIPPED non-recurring shift (no real shift for this date): ${nonRecurringShift.name} [ID: ${nonRecurringShift.id}]`);
      }
    });

    // Sort by start time
    availableShifts.sort((a, b) => new Date(a.startTime) - new Date(b.startTime));

    console.log(`Final available shifts count: ${availableShifts.length}`);
    availableShifts.forEach(shift => {
      console.log(`  Available: ${shift.name} (${shift.startTime.toISOString()} - ${shift.endTime.toISOString()}) [${shift.isReal ? 'Real' : 'Recurring'}]`);
    });

    res.json(availableShifts);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch available shifts', details: err.message });
  }
});

// ADMIN: Check in a user for a shift (by userId and shiftId only)
app.post('/api/admin/checkin', async (req, res) => {
  try {
    const { userId, shiftId } = req.body;
    if (!userId || !shiftId) {
      return res.status(400).json({ error: 'userId and shiftId are required' });
    }

    console.log(`\n=== CHECK-IN DEBUG ===`);
    console.log(`- User ID: ${userId}`);
    console.log(`- Shift ID: ${shiftId}`);

    // Find the existing signup for this user and shift
    let signup = await prisma.shiftSignup.findFirst({
      where: { 
        userId: parseInt(userId), 
        shiftId: parseInt(shiftId) 
      },
      include: {
        user: { select: { firstName: true, lastName: true, email: true } },
        shift: { select: { name: true, startTime: true, endTime: true } }
      }
    });

    if (!signup) {
      console.log(`- No signup found for user ${userId} and shift ${shiftId}`);
      return res.status(404).json({ error: 'User is not registered for this shift' });
    }

    console.log(`- Found signup: ${signup.user.firstName} ${signup.user.lastName} for shift "${signup.shift.name}"`);
    console.log(`- Current check-in: ${signup.checkIn}`);
    console.log(`- Current check-out: ${signup.checkOut}`);

    // Update the signup with check-in time
    signup = await prisma.shiftSignup.update({
      where: { id: signup.id },
      data: { checkIn: new Date() },
    });

    console.log(`- Updated check-in: ${signup.checkIn}`);
    console.log(`=== END CHECK-IN DEBUG ===\n`);

    res.json({
      id: signup.id,
      checkIn: signup.checkIn,
      checkOut: signup.checkOut,
    });
  } catch (err) {
    console.error('Check-in error:', err);
    res.status(500).json({ error: 'Failed to check in', details: err.message });
  }
});

// ADMIN: Check out a user for a shift (by userId and shiftId only)
app.post('/api/admin/checkout', async (req, res) => {
  try {
    const { userId, shiftId } = req.body;
    if (!userId || !shiftId) {
      return res.status(400).json({ error: 'userId and shiftId are required' });
    }

    console.log(`\n=== CHECK-OUT DEBUG ===`);
    console.log(`- User ID: ${userId}`);
    console.log(`- Shift ID: ${shiftId}`);

    // Find the existing signup for this user and shift
    let signup = await prisma.shiftSignup.findFirst({
      where: { 
        userId: parseInt(userId), 
        shiftId: parseInt(shiftId) 
      },
      include: {
        user: { select: { firstName: true, lastName: true, email: true } },
        shift: { select: { name: true, startTime: true, endTime: true } }
      }
    });

    if (!signup) {
      console.log(`- No signup found for user ${userId} and shift ${shiftId}`);
      return res.status(404).json({ error: 'User is not registered for this shift' });
    }

    console.log(`- Found signup: ${signup.user.firstName} ${signup.user.lastName} for shift "${signup.shift.name}"`);
    console.log(`- Current check-in: ${signup.checkIn}`);
    console.log(`- Current check-out: ${signup.checkOut}`);

    // Update the signup with check-out time
    signup = await prisma.shiftSignup.update({
      where: { id: signup.id },
      data: { checkOut: new Date() },
    });

    console.log(`- Updated check-out: ${signup.checkOut}`);
    console.log(`=== END CHECK-OUT DEBUG ===\n`);

    res.json({
      id: signup.id,
      checkIn: signup.checkIn,
      checkOut: signup.checkOut,
    });
  } catch (err) {
    console.error('Check-out error:', err);
    res.status(500).json({ error: 'Failed to check out', details: err.message });
  }
});

// ADMIN: Get users registered for a specific shift
app.get('/api/admin/shift-users', async (req, res) => {
  try {
    const { shiftId, date, organizationId } = req.query;
    if (!shiftId || !date || !organizationId) {
      return res.status(400).json({ error: 'shiftId, date, and organizationId are required' });
    }

    console.log(`\n=== SHIFT USERS DEBUG for shift ${shiftId} on ${date} ===`);
    
    // Check if it's a recurring shift or real shift
    let realShiftId = shiftId;
    if (shiftId.startsWith('recurring-')) {
      // It's a recurring shift template, we need to find or create the real shift
      const parts = shiftId.split('-');
      const recurringId = parseInt(parts[1]);
      const shiftDate = date;
      
      console.log(`- Recurring shift ID: ${recurringId}, Date: ${shiftDate}`);
      
      // Check if a real shift exists for this date/template
      const start = new Date(shiftDate + 'T00:00:00');
      const end = new Date(shiftDate + 'T23:59:59');
      
      const existingRealShift = await prisma.shift.findFirst({
        where: {
          recurringShiftId: recurringId,
          organizationId: parseInt(organizationId),
          startTime: { gte: start, lte: end },
        },
      });
      
      if (existingRealShift) {
        realShiftId = existingRealShift.id.toString();
        console.log(`- Found existing real shift: ${realShiftId}`);
      } else {
        console.log(`- No real shift exists for this recurring template on this date`);
        return res.json([]);
      }
    } else {
      console.log(`- Real shift ID: ${realShiftId}`);
    }

    // Find all users who have signups for this specific shift
    const signups = await prisma.shiftSignup.findMany({
      where: {
        shiftId: parseInt(realShiftId),
      },
      include: {
        user: {
          select: { id: true, firstName: true, lastName: true, email: true, role: true },
        },
      },
    });

    console.log(`- Found ${signups.length} signups for shift ${realShiftId}`);
    signups.forEach((signup, index) => {
      console.log(`  ${index + 1}. User: ${signup.user.firstName} ${signup.user.lastName} - Email: ${signup.user.email}`);
    });

    // Extract unique users from signups
    const userMap = new Map();
    signups.forEach(signup => {
      if (!userMap.has(signup.user.id)) {
        userMap.set(signup.user.id, signup.user);
      }
    });

    const users = Array.from(userMap.values());
    console.log(`- Returning ${users.length} unique users`);
    
    res.json(users);
  } catch (err) {
    console.error('Error fetching shift users:', err);
    res.status(500).json({ error: 'Failed to fetch shift users', details: err.message });
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

// Get donations by user with date filtering
app.get('/api/donations/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { date, week } = req.query;
    
    if (!userId) return res.status(400).json({ error: 'userId is required' });

    // Build where clause for date filtering
    let dateFilter = {};
    if (date) {
      const startDate = new Date(date + 'T00:00:00Z');
      const endDate = new Date(date + 'T23:59:59Z');
      dateFilter = {
        createdAt: {
          gte: startDate,
          lte: endDate
        }
      };
    } else if (week) {
      const startOfWeek = new Date(week + 'T00:00:00Z');
      const endOfWeek = new Date(startOfWeek);
      endOfWeek.setDate(endOfWeek.getDate() + 6);
      endOfWeek.setHours(23, 59, 59, 999);
      dateFilter = {
        createdAt: {
          gte: startOfWeek,
          lte: endOfWeek
        }
      };
    }

    const donations = await prisma.donation.findMany({
      where: {
        shiftSignup: {
          userId: parseInt(userId)
        },
        ...dateFilter
      },
      include: {
        donor: true,
        shift: {
          include: {
            shiftCategory: true
          }
        },
        items: {
          include: {
            category: true
          }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    console.log(`Found ${donations.length} donations for user ${userId}`);
    res.json(donations);
  } catch (err) {
    console.error('Error fetching user donations:', err);
    res.status(500).json({ error: 'Failed to fetch user donations', details: err.message });
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

// 1. GET /api/terms-and-conditions/:organizationId/active (single document - for backward compatibility)
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

// 2. GET /api/terms-and-conditions/:organizationId/all-active (multiple documents)
app.get('/api/terms-and-conditions/:organizationId/all-active', async (req, res) => {
  try {
    const { organizationId } = req.params;
    const terms = await prisma.termsAndConditions.findMany({
      where: {
        organizationId: parseInt(organizationId),
        isActive: true
      },
      orderBy: { version: 'asc' }
    });
    if (!terms || terms.length === 0) return res.status(404).json({ error: 'No active terms found' });
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
    
    // Get ALL real shifts for this date (including inactive ones)
    const allRealShifts = await prisma.shift.findMany({
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
        RecurringShift: true, // Include to check recurring shift status
      },
      orderBy: { startTime: 'asc' },
    });

    // Filter shifts based on isActive status
    const realShifts = allRealShifts.filter(shift => {
      // If this shift has a recurringShiftId, check both Shift.isActive AND RecurringShift.isActive
      if (shift.recurringShiftId && shift.RecurringShift) {
        return shift.isActive && shift.RecurringShift.isActive;
      }
      // If no recurringShiftId, just check Shift.isActive
      return shift.isActive;
    });

    // Get recurring shift templates
    const dayOfWeek = start.getDay();
    const recurringTemplates = await prisma.recurringShift.findMany({
      where: {
        organizationId: parseInt(organizationId),
        dayOfWeek,
        isActive: true, // Only show active recurring shifts
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
      isRecurring: shift.recurringShiftId ? true : false,
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
            recurringShiftId: template.id, // Link to the recurring template
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

// Cancel a shift signup
app.delete('/api/my-shifts/:signupId', async (req, res) => {
  try {
    const { signupId } = req.params;
    if (!signupId) return res.status(400).json({ error: 'signupId is required' });

    // Find the signup
    const signup = await prisma.shiftSignup.findUnique({
      where: { id: parseInt(signupId) },
      include: { shift: true }
    });
    
    if (!signup) {
      return res.status(404).json({ error: 'Shift signup not found' });
    }

    // Check if already checked in
    if (signup.checkIn) {
      return res.status(400).json({ error: 'Cannot cancel a shift that has already been checked in' });
    }

    // Delete the signup
    await prisma.shiftSignup.delete({
      where: { id: parseInt(signupId) },
    });

    res.json({ message: 'Shift cancelled successfully' });
  } catch (err) {
    console.error('Cancel shift error:', err);
    res.status(500).json({ error: 'Failed to cancel shift', details: err.message });
  }
});

// Get organization details by ID
app.get('/api/organization/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return res.status(400).json({ error: 'organization ID is required' });

    const organization = await prisma.organization.findUnique({
      where: { id: parseInt(id) },
      select: { id: true, name: true, email: true, address: true },
    });

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    res.json(organization);
  } catch (err) {
    console.error('Get organization error:', err);
    res.status(500).json({ error: 'Failed to get organization', details: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Server accessible at:`);
  console.log(`- http://localhost:${PORT}`);
  console.log(`- http://127.0.0.1:${PORT}`);
  console.log(`- http://172.20.10.2:${PORT}`);  // Your computer's IP
}); 