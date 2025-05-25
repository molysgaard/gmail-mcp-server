/**
 * Utility functions for Gmail MCP Server
 * Provides email formatting, encoding, and validation utilities
 */

import { 
    validateEmail as validateEmailAdvanced, 
    validateMimeType, 
    validateEmailContent, 
    ValidationError 
} from './error-handler.js';

/**
 * Helper function to encode email headers containing non-ASCII characters
 * according to RFC 2047 MIME specification
 */
function encodeEmailHeader(text: string): string {
    // Only encode if the text contains non-ASCII characters
    if (/[^\x00-\x7F]/.test(text)) {
        // Use MIME Words encoding (RFC 2047)
        return '=?UTF-8?B?' + Buffer.from(text).toString('base64') + '?=';
    }
    return text;
}

/**
 * Simple email validation for backward compatibility
 */
export const validateEmail = (email: string): boolean => {
    return validateEmailAdvanced(email).valid;
};

/**
 * Creates a properly formatted email message with appropriate headers and MIME structure
 * @param validatedArgs - Validated email parameters
 * @returns Formatted email message string
 * @throws ValidationError if email parameters are invalid
 */
export function createEmailMessage(validatedArgs: any): string {
    // Validate subject
    if (!validatedArgs.subject || validatedArgs.subject.trim() === '') {
        throw new ValidationError('Email subject cannot be empty', { 'subject': ['Subject is required'] });
    }

    // Check if body or htmlBody is provided
    if (!validatedArgs.body && !validatedArgs.htmlBody) {
        throw new ValidationError('Email must have content', {
            'body': ['Either body or htmlBody must be provided']
        });
    }

    // Validate email content
    if (validatedArgs.body) {
        const bodyValidation = validateEmailContent(validatedArgs.body);
        if (!bodyValidation.valid) {
            throw new ValidationError(bodyValidation.reason || 'Invalid email body', {
                'body': [bodyValidation.reason || 'Invalid content']
            });
        }
    }

    if (validatedArgs.htmlBody) {
        const htmlValidation = validateEmailContent(validatedArgs.htmlBody, true);
        if (!htmlValidation.valid) {
            throw new ValidationError(htmlValidation.reason || 'Invalid HTML body', {
                'htmlBody': [htmlValidation.reason || 'Invalid HTML content']
            });
        }
    }

    const encodedSubject = encodeEmailHeader(validatedArgs.subject);
    
    // Determine content type based on available content and explicit mimeType
    let mimeType = validatedArgs.mimeType || 'text/plain';
    
    // Validate MIME type if provided
    if (validatedArgs.mimeType) {
        const mimeValidation = validateMimeType(validatedArgs.mimeType);
        if (!mimeValidation.valid) {
            throw new ValidationError(mimeValidation.reason || 'Invalid MIME type', {
                'mimeType': [mimeValidation.reason || 'Invalid format']
            });
        }
    }
    
    // If htmlBody is provided and mimeType isn't explicitly set to text/plain,
    // use multipart/alternative to include both versions
    if (validatedArgs.htmlBody && mimeType !== 'text/plain') {
        mimeType = 'multipart/alternative';
    }

    // Generate a random boundary string for multipart messages
    const boundary = `----=_NextPart_${Math.random().toString(36).substring(2)}`;

    // Validate email addresses
    const invalidEmails: {email: string, reason?: string}[] = [];
    
    // Validate 'to' recipients
    (validatedArgs.to as string[]).forEach(email => {
        const validation = validateEmailAdvanced(email);
        if (!validation.valid) {
            invalidEmails.push({
                email,
                reason: validation.reason
            });
        }
    });
    
    // Validate 'cc' recipients if present
    if (validatedArgs.cc) {
        (validatedArgs.cc as string[]).forEach(email => {
            const validation = validateEmailAdvanced(email);
            if (!validation.valid) {
                invalidEmails.push({
                    email,
                    reason: validation.reason
                });
            }
        });
    }
    
    // Validate 'bcc' recipients if present
    if (validatedArgs.bcc) {
        (validatedArgs.bcc as string[]).forEach(email => {
            const validation = validateEmailAdvanced(email);
            if (!validation.valid) {
                invalidEmails.push({
                    email,
                    reason: validation.reason
                });
            }
        });
    }
    
    // If any emails are invalid, throw a validation error
    if (invalidEmails.length > 0) {
        const fieldErrors: Record<string, string[]> = {};
        
        invalidEmails.forEach(({ email, reason }) => {
            fieldErrors[email] = [`Invalid email: ${reason || 'unknown error'}`];
        });
        
        throw new ValidationError('One or more email addresses are invalid', fieldErrors);
    }

    // Common email headers
    const emailParts = [
        'From: me',
        `To: ${validatedArgs.to.join(', ')}`,
        validatedArgs.cc ? `Cc: ${validatedArgs.cc.join(', ')}` : '',
        validatedArgs.bcc ? `Bcc: ${validatedArgs.bcc.join(', ')}` : '',
        `Subject: ${encodedSubject}`,
        // Add thread-related headers if specified
        validatedArgs.inReplyTo ? `In-Reply-To: ${validatedArgs.inReplyTo}` : '',
        validatedArgs.inReplyTo ? `References: ${validatedArgs.inReplyTo}` : '',
        'MIME-Version: 1.0',
    ].filter(Boolean);

    // Construct the email based on the content type
    if (mimeType === 'multipart/alternative') {
        // Multipart email with both plain text and HTML
        emailParts.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
        emailParts.push('');
        
        // Plain text part
        emailParts.push(`--${boundary}`);
        emailParts.push('Content-Type: text/plain; charset=UTF-8');
        emailParts.push('Content-Transfer-Encoding: 7bit');
        emailParts.push('');
        emailParts.push(validatedArgs.body || '');
        emailParts.push('');
        
        // HTML part
        emailParts.push(`--${boundary}`);
        emailParts.push('Content-Type: text/html; charset=UTF-8');
        emailParts.push('Content-Transfer-Encoding: 7bit');
        emailParts.push('');
        emailParts.push(validatedArgs.htmlBody || validatedArgs.body || '');
        emailParts.push('');
        
        // Close the boundary
        emailParts.push(`--${boundary}--`);
    } else if (mimeType === 'text/html') {
        // HTML-only email
        emailParts.push('Content-Type: text/html; charset=UTF-8');
        emailParts.push('Content-Transfer-Encoding: 7bit');
        emailParts.push('');
        emailParts.push(validatedArgs.htmlBody || validatedArgs.body || '');
    } else {
        // Plain text email (default)
        emailParts.push('Content-Type: text/plain; charset=UTF-8');
        emailParts.push('Content-Transfer-Encoding: 7bit');
        emailParts.push('');
        emailParts.push(validatedArgs.body || '');
    }

    return emailParts.join('\r\n');
}