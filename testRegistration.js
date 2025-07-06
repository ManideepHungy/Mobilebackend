require('dotenv').config();
const { PrismaClient } = require('./generated/prisma');

const prisma = new PrismaClient();

async function testRegistration() {
  try {
    // Test data
    const testData = {
      email: `test-${Date.now()}@example.com`,
      password: 'testpass123',
      firstName: 'Test',
      lastName: 'User',
      organizationId: 1, // Make sure this organization exists
      signature: 'Test Digital Signature',
      agreeToTerms: true
    };

    console.log('Testing registration with data:', testData);

    // Check if organization exists
    const org = await prisma.organization.findUnique({
      where: { id: testData.organizationId }
    });

    if (!org) {
      console.error('Organization with ID 1 does not exist. Please create one first.');
      return;
    }

    console.log('Organization found:', org.name);

    // Check if there are active terms and conditions
    const terms = await prisma.termsAndConditions.findFirst({
      where: {
        organizationId: testData.organizationId,
        isActive: true
      }
    });

    if (!terms) {
      console.error('No active terms and conditions found for organization. Please create one first.');
      return;
    }

    console.log('Terms and conditions found:', terms.title);

    // Simulate the registration process
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(testData.password, 10);

    // Create user
    const user = await prisma.user.create({
      data: {
        email: testData.email,
        password: hashedPassword,
        firstName: testData.firstName,
        lastName: testData.lastName,
        organizationId: testData.organizationId,
        role: 'VOLUNTEER',
        status: 'PENDING'
      }
    });

    console.log('User created:', user.id);

    // Generate PDF and upload (simplified version)
    const PDFDocument = require('pdfkit');
    const CloudflareR2Service = require('./cloudflareR2');

    const doc = new PDFDocument({ margin: 40 });
    let buffers = [];
    doc.on('data', buffers.push.bind(buffers));

    const pdfPromise = new Promise(async (resolve, reject) => {
      doc.on('end', async () => {
        try {
          const pdfBuffer = Buffer.concat(buffers);
          const uploadResult = await CloudflareR2Service.uploadSignedDocument(
            pdfBuffer,
            user.id.toString(),
            testData.organizationId.toString()
          );
          resolve(uploadResult.url);
        } catch (uploadError) {
          console.error('Failed to upload signed PDF:', uploadError);
          reject(uploadError);
        }
      });
    });

    // Generate PDF content
    doc.fontSize(18).text('SIGNED AGREEMENT', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text('User Information:', { underline: true });
    doc.text(`- Name: ${testData.firstName} ${testData.lastName}`);
    doc.text(`- Email: ${testData.email}`);
    doc.text(`- Organization: ${org.name}`);
    doc.moveDown();
    doc.text('Terms & Conditions:', { underline: true });
    doc.text(`- Document: ${terms.title}`);
    doc.text(`- Version: ${terms.version}`);
    doc.moveDown();
    doc.text(`Signed Date: ${new Date().toISOString()}`);
    doc.moveDown(2);
    doc.fontSize(14).text('Digital Signature:', { underline: true });
    doc.moveDown();
    doc.fontSize(16).text(testData.signature, { align: 'right' });
    doc.end();

    // Wait for PDF upload
    const signedDocumentUrl = await pdfPromise;
    console.log('PDF uploaded successfully:', signedDocumentUrl);

    // Create user agreement
    const userAgreement = await prisma.userAgreement.create({
      data: {
        userId: user.id,
        organizationId: testData.organizationId,
        termsAndConditionsId: terms.id,
        signature: testData.signature,
        signedDocumentUrl: signedDocumentUrl,
        ipAddress: '127.0.0.1',
        userAgent: 'Test Script',
      }
    });

    console.log('User agreement created:', userAgreement.id);
    console.log('Signed document URL saved:', userAgreement.signedDocumentUrl);

    // Verify the URL was saved
    const savedAgreement = await prisma.userAgreement.findUnique({
      where: { id: userAgreement.id }
    });

    console.log('Verification - Saved agreement:');
    console.log('- ID:', savedAgreement.id);
    console.log('- User ID:', savedAgreement.userId);
    console.log('- Signed Document URL:', savedAgreement.signedDocumentUrl);
    console.log('- Is URL null/empty?', !savedAgreement.signedDocumentUrl);

    if (savedAgreement.signedDocumentUrl) {
      console.log('✅ SUCCESS: Signed document URL was saved to database!');
    } else {
      console.log('❌ FAILED: Signed document URL is null/empty in database');
    }

  } catch (error) {
    console.error('Test failed:', error);
  } finally {
    await prisma.$disconnect();
  }
}

testRegistration(); 