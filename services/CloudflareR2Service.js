const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

class CloudflareR2Service {
  constructor() {
    this.client = new S3Client({
      region: 'auto',
      endpoint: process.env.CLOUDFLARE_R2_ENDPOINT,
      credentials: {
        accessKeyId: process.env.CLOUDFLARE_R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY,
      },
    });
    this.bucketName = process.env.CLOUDFLARE_R2_BUCKET_NAME;
    this.publicUrl = process.env.CLOUDFLARE_R2_PUBLIC_URL;
    console.log('CloudflareR2Service constructor', this.publicUrl);
    console.log('CloudflareR2Service constructor', this.bucketName);
    console.log('CloudflareR2Service constructor', this.client);
    console.log('CloudflareR2Service constructor', this.client.config.credentials);
    console.log('CloudflareR2Service constructor', this.client.config.region);
    console.log('CloudflareR2Service constructor', this.client.config.endpoint);
    console.log('CloudflareR2Service constructor', this.client.config.credentials);
    console.log('CloudflareR2Service constructor', this.client.config.region);  
  }

  async uploadSignedDocument(documentBuffer, userId, organizationId) {
    try {
      const fileName = `signed-documents/${organizationId}/${userId}/${Date.now()}-signed-agreement.txt`;
      
      const command = new PutObjectCommand({
        Bucket: this.bucketName,
        Key: fileName,
        Body: documentBuffer,
        ContentType: 'text/plain',
        Metadata: {
          'user-id': userId,
          'organization-id': organizationId,
          'upload-date': new Date().toISOString(),
        },
      });

      await this.client.send(command);

      // Generate a public URL (if bucket is public) or signed URL
      const url = `${process.env.CLOUDFLARE_R2_PUBLIC_URL}/${fileName}`;
      
      return {
        url,
        fileName,
        bucket: this.bucketName,
      };
    } catch (error) {
      console.error('Error uploading to R2:', error);
      throw new Error('Failed to upload signed document to R2');
    }
  }

  async generateSignedUrl(fileName, expiresIn = 3600) {
    try {
      const command = new GetObjectCommand({
        Bucket: this.bucketName,
        Key: fileName,
      });

      const signedUrl = await getSignedUrl(this.client, command, { expiresIn });
      return signedUrl;
    } catch (error) {
      console.error('Error generating signed URL:', error);
      throw new Error('Failed to generate signed URL');
    }
  }

  async uploadFile(fileBuffer, fileName, contentType = 'application/octet-stream') {
    try {
      const command = new PutObjectCommand({
        Bucket: this.bucketName,
        Key: fileName,
        Body: fileBuffer,
        ContentType: contentType,
      });

      await this.client.send(command);

      const url = `${process.env.CLOUDFLARE_R2_PUBLIC_URL}/${fileName}`;
      
      return {
        url,
        fileName,
        bucket: this.bucketName,
      };
    } catch (error) {
      console.error('Error uploading file to R2:', error);
      throw new Error('Failed to upload file to R2');
    }
  }
}

// Create a singleton instance
const cloudflareR2Service = new CloudflareR2Service();

module.exports = cloudflareR2Service; 