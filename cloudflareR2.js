const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

// Cloudflare R2 configuration
const R2_ACCESS_KEY_ID = process.env.CLOUDFLARE_R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY;
const R2_BUCKET_NAME = process.env.CLOUDFLARE_R2_BUCKET_NAME || 'hungy-documents';
const R2_ENDPOINT = process.env.CLOUDFLARE_R2_ENDPOINT;

// Initialize S3 client for R2
const r2Client = new S3Client({
  region: 'auto',
  endpoint: R2_ENDPOINT,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY,
  },
});

class CloudflareR2Service {
  /**
   * Upload a file to R2 bucket
   * @param {Buffer} fileBuffer - File content as buffer
   * @param {string} fileName - Name of the file
   * @param {string} contentType - MIME type of the file
   * @param {string} folder - Folder path in bucket (optional)
   * @returns {Promise<{url: string, key: string}>}
   */
  static async uploadFile(fileBuffer, fileName, contentType, folder = '') {
    try {
      const key = folder ? `${folder}/${fileName}` : fileName;
      
      const command = new PutObjectCommand({
        Bucket: R2_BUCKET_NAME,
        Key: key,
        Body: fileBuffer,
        ContentType: contentType,
        ACL: 'public-read', // Make file publicly accessible
      });

      await r2Client.send(command);
      
      // Return the public URL using the public URL from environment
      const publicUrl = `${process.env.CLOUDFLARE_R2_PUBLIC_URL}/${key}`;
      
      return {
        url: publicUrl,
        key: key,
      };
    } catch (error) {
      console.error('R2 upload error:', error);
      throw new Error('Failed to upload file to R2');
    }
  }

  /**
   * Generate a signed URL for file access (if needed for private files)
   * @param {string} key - File key in bucket
   * @param {number} expiresIn - Expiration time in seconds (default: 1 hour)
   * @returns {Promise<string>}
   */
  static async getSignedUrl(key, expiresIn = 3600) {
    try {
      const command = new GetObjectCommand({
        Bucket: R2_BUCKET_NAME,
        Key: key,
      });

      const signedUrl = await getSignedUrl(r2Client, command, { expiresIn });
      return signedUrl;
    } catch (error) {
      console.error('R2 signed URL error:', error);
      throw new Error('Failed to generate signed URL');
    }
  }

  /**
   * Upload a signed document (PDF with signature)
   * @param {Buffer} pdfBuffer - PDF content as buffer
   * @param {string} userId - User ID
   * @param {string} organizationId - Organization ID
   * @returns {Promise<{url: string, key: string}>}
   */
  static async uploadSignedDocument(pdfBuffer, userId, organizationId) {
    const fileName = `signed-agreement-${userId}-${organizationId}-${Date.now()}.pdf`;
    const folder = 'signed-documents';
    
    return await this.uploadFile(
      pdfBuffer,
      fileName,
      'application/pdf',
      folder
    );
  }

  /**
   * Upload terms and conditions document
   * @param {Buffer} fileBuffer - File content as buffer
   * @param {string} fileName - Original file name
   * @param {string} organizationId - Organization ID
   * @returns {Promise<{url: string, key: string}>}
   */
  static async uploadTermsDocument(fileBuffer, fileName, organizationId) {
    const timestamp = Date.now();
    const newFileName = `terms-${organizationId}-${timestamp}-${fileName}`;
    const folder = 'terms-and-conditions';
    
    return await this.uploadFile(
      fileBuffer,
      newFileName,
      'application/pdf',
      folder
    );
  }
}

module.exports = CloudflareR2Service; 