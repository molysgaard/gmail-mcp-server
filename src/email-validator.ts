/**
 * Advanced email validation for Gmail MCP Server
 * Provides comprehensive validation for email addresses, content, and attachments
 */

import { ValidationError } from './error-handler.js';
import { logger } from './error-logger.js';

/**
 * Result of email validation
 */
export interface ValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Advanced email address validation with proper error messages
 * @param email Email address to validate
 * @returns Validation result with reason if invalid
 */
export function validateEmailAddress(email: string): ValidationResult {
  // Validate email address format
  if (!email || typeof email !== 'string') {
    return { valid: false, reason: 'Email address cannot be empty' };
  }

  // Basic email format validation
  const basicEmailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!basicEmailRegex.test(email)) {
    return { valid: false, reason: 'Invalid email format' };
  }

  // Extract parts of the email
  const parts = email.split('@');
  const localPart = parts[0];
  const domainPart = parts[1];

  // Check for invalid characters in local part
  if (!/^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(localPart)) {
    return { 
      valid: false, 
      reason: 'Local part contains invalid characters' 
    };
  }

  // Check domain part
  if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domainPart)) {
    return { 
      valid: false, 
      reason: 'Domain part is invalid' 
    };
  }

  // Check for consecutive dots
  if (email.includes('..')) {
    return { 
      valid: false, 
      reason: 'Email contains consecutive dots' 
    };
  }

  // Check for common typos in domain part
  const commonTypoDomains = [
    'gmial.com', 'gmai.com', 'gmail.co', 'gmail.comm',
    'hotmial.com', 'hotmai.com', 'hotmail.co', 'hotmail.comm',
    'yahooo.com', 'yahoo.co', 'yahoo.comm'
  ];
  
  if (commonTypoDomains.includes(domainPart)) {
    return { 
      valid: false, 
      reason: `Possible typo in domain: ${domainPart}` 
    };
  }

  return { valid: true };
}

/**
 * Validate email recipients and throw detailed ValidationError for any issues
 * @param recipients Email addresses to validate
 * @param type Type of recipients (to, cc, bcc)
 * @throws ValidationError if any recipients are invalid
 */
export function validateRecipients(recipients: string[], type: 'to' | 'cc' | 'bcc'): void {
  if (!recipients || !Array.isArray(recipients)) {
    throw new ValidationError(`${type} must be an array`, {
      [type]: ['Must be an array of email addresses']
    });
  }

  if (type === 'to' && recipients.length === 0) {
    throw new ValidationError('At least one recipient is required', {
      'to': ['At least one recipient is required']
    });
  }

  const invalidEmails: {email: string, reason: string}[] = [];
  
  for (const email of recipients) {
    const result = validateEmailAddress(email);
    if (!result.valid) {
      invalidEmails.push({
        email,
        reason: result.reason || 'Invalid email format'
      });
    }
  }

  if (invalidEmails.length > 0) {
    const fieldErrors: Record<string, string[]> = {};
    fieldErrors[type] = invalidEmails.map(
      ({ email, reason }) => `"${email}": ${reason}`
    );
    
    throw new ValidationError(`Invalid email address(es) in ${type} field`, fieldErrors);
  }
}

/**
 * Enhanced MIME type validation
 * @param mimeType MIME type to validate
 * @returns Validation result
 */
export function validateMimeType(mimeType: string): ValidationResult {
  if (!mimeType || typeof mimeType !== 'string') {
    return { valid: false, reason: 'MIME type must be a non-empty string' };
  }

  // Check for basic MIME type format (type/subtype)
  const mimeRegex = /^[-\w.]+\/[-\w.+]+$/;
  if (!mimeRegex.test(mimeType)) {
    return { valid: false, reason: 'Invalid MIME type format' };
  }

  return { valid: true };
}

/**
 * Content validation for email body
 * @param content Content to validate
 * @param isHtml Whether content is HTML
 * @returns Validation result
 */
export function validateEmailContent(content: string, isHtml: boolean = false): ValidationResult {
  if (content === undefined || content === null) {
    return { valid: false, reason: 'Email content cannot be null or undefined' };
  }

  if (typeof content !== 'string') {
    return { valid: false, reason: 'Email content must be a string' };
  }

  if (content.trim().length === 0) {
    return { valid: false, reason: 'Email content cannot be empty' };
  }

  if (isHtml) {
    // Simple check for potentially malicious HTML
    const suspiciousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript\s*:/gi,
      /onerror\s*=/gi,
      /onclick\s*=/gi
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(content)) {
        return { 
          valid: false, 
          reason: 'HTML content contains potentially unsafe scripts or event handlers' 
        };
      }
    }
  }

  return { valid: true };
}

/**
 * Validates an entire email request
 * @param emailData Email data to validate
 * @throws ValidationError if validation fails
 */
export function validateEmail(emailData: any): void {
  // Validate required fields
  if (!emailData) {
    throw new ValidationError('Email data is required', {
      'general': ['Email data cannot be empty']
    });
  }
  
  // Validate subject
  if (!emailData.subject || emailData.subject.trim() === '') {
    throw new ValidationError('Email subject cannot be empty', { 
      'subject': ['Subject is required'] 
    });
  }
  
  // Validate content (body or htmlBody must be provided)
  if (!emailData.body && !emailData.htmlBody) {
    throw new ValidationError('Email must have content', {
      'body': ['Either body or htmlBody must be provided']
    });
  }
  
  // Validate recipients
  validateRecipients(emailData.to, 'to');
  
  if (emailData.cc && emailData.cc.length > 0) {
    validateRecipients(emailData.cc, 'cc');
  }
  
  if (emailData.bcc && emailData.bcc.length > 0) {
    validateRecipients(emailData.bcc, 'bcc');
  }
  
  // Validate body content
  if (emailData.body) {
    const bodyResult = validateEmailContent(emailData.body);
    if (!bodyResult.valid) {
      throw new ValidationError(bodyResult.reason || 'Invalid email body', {
        'body': [bodyResult.reason || 'Invalid content']
      });
    }
  }
  
  // Validate HTML content if provided
  if (emailData.htmlBody) {
    const htmlResult = validateEmailContent(emailData.htmlBody, true);
    if (!htmlResult.valid) {
      throw new ValidationError(htmlResult.reason || 'Invalid HTML body', {
        'htmlBody': [htmlResult.reason || 'Invalid HTML content']
      });
    }
  }
  
  // Validate MIME type if provided
  if (emailData.mimeType) {
    const mimeResult = validateMimeType(emailData.mimeType);
    if (!mimeResult.valid) {
      throw new ValidationError(mimeResult.reason || 'Invalid MIME type', {
        'mimeType': [mimeResult.reason || 'Invalid format']
      });
    }
  }
  
  logger.debug('Email validation successful', { 
    subject: emailData.subject,
    recipientCount: emailData.to.length
  });
}
