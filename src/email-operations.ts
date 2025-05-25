/**
 * Email operations module for Gmail MCP Server
 * Handles sending, drafting, searching, and reading emails
 */

import { google, gmail_v1 } from 'googleapis';
import { getOAuth2Client } from './auth.js';
import { ValidationError, GmailApiError, RateLimitError, AuthenticationError } from './error-handler.js';
import { logger } from './error-logger.js';
import { validateEmailAddress, validateEmailContent } from './email-validator.js';
import { createEmailMessage } from './utl.js';

// Type definitions for Gmail API responses
export interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}

export interface EmailAttachment {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}

export interface EmailContent {
    text: string;
    html: string;
}

/**
 * Helper function to wrap API calls with error handling
 * @param apiCall Function that makes the API call
 * @param errorMessage Message to use if the call fails
 * @returns Result of the API call
 */
export async function withApiErrorHandling<T>(apiCall: () => Promise<T>, errorMessage: string): Promise<T> {
    try {
        return await apiCall();
    } catch (error: any) {
        logger.error(`API Error: ${errorMessage}`, { errorDetails: error.message });
        
        // Check for specific error types
        if (error.code === 401 || error.code === 403) {
            throw new AuthenticationError(`Authentication error: ${error.message}`);
        }
        
        if (error.code === 429 || (error.message && error.message.includes('quota'))) {
            throw new RateLimitError('Rate limit exceeded', 3600); // Suggest retry after 1 hour
        }
        
        // Generic API error
        throw new GmailApiError(
            `${errorMessage}: ${error.message || 'Unknown error'}`,
            error.code || 500,
            error.errors?.[0]?.reason || 'api_error'
        );
    }
}

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
export function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    // Initialize containers for different content types
    let textContent = '';
    let htmlContent = '';

    // If the part has a body with data, process it based on MIME type
    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');

        // Store content based on its MIME type
        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }

    // If the part has nested parts, recursively process them
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }

    // Return both plain text and HTML content
    return { text: textContent, html: htmlContent };
}

/**
 * Get Gmail API client
 * @returns Gmail API client
 */
export function getGmailClient(): gmail_v1.Gmail {
    const oauth2Client = getOAuth2Client();
    return google.gmail({ version: 'v1', auth: oauth2Client });
}

/**
 * Send an email
 * @param emailData Email data to send
 * @returns Response from Gmail API
 */
export async function sendEmail(emailData: any): Promise<any> {
    try {
        // Validate email data
        validateEmail(emailData);
        
        // Create email message
        const rawMessage = await createEmailMessage({
            to: emailData.to.join(','),
            cc: emailData.cc ? emailData.cc.join(',') : undefined,
            bcc: emailData.bcc ? emailData.bcc.join(',') : undefined,
            subject: emailData.subject,
            text: typeof emailData.body === 'string' ? emailData.body : emailData.body.text,
            html: typeof emailData.body === 'string' ? undefined : emailData.body.html
        });
        
        // Encode message in base64url format
        const encodedMessage = Buffer.from(rawMessage).toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
        
        // Create message request
        const messageRequest: { raw: string; threadId?: string } = {
            raw: encodedMessage
        };
        
        // Add threadId if provided
        if (emailData.threadId) {
            messageRequest.threadId = emailData.threadId;
        }
        
        // Send email
        const gmail = getGmailClient();
        const response = await withApiErrorHandling(
            () => gmail.users.messages.send({
                userId: 'me',
                requestBody: messageRequest
            }),
            'Failed to send email'
        );
        
        logger.info('Email sent successfully', { messageId: response.data.id });
        return response.data;
    } catch (error: any) {
        logger.error('Failed to send email', { error: error.message });
        throw error;
    }
}

/**
 * Create an email draft
 * @param emailData Email data to draft
 * @returns Response from Gmail API
 */
export async function createDraft(emailData: any): Promise<any> {
    try {
        // Validate email data
        validateEmail(emailData);
        
        // Create email message
        const rawMessage = await createEmailMessage({
            to: emailData.to.join(','),
            cc: emailData.cc ? emailData.cc.join(',') : undefined,
            bcc: emailData.bcc ? emailData.bcc.join(',') : undefined,
            subject: emailData.subject,
            text: typeof emailData.body === 'string' ? emailData.body : emailData.body.text,
            html: typeof emailData.body === 'string' ? undefined : emailData.body.html
        });
        
        // Encode message in base64url format
        const encodedMessage = Buffer.from(rawMessage).toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
        
        // Create message request
        const messageRequest: { raw: string; threadId?: string } = {
            raw: encodedMessage
        };
        
        // Add threadId if provided
        if (emailData.threadId) {
            messageRequest.threadId = emailData.threadId;
        }
        
        // Create draft
        const gmail = getGmailClient();
        const response = await withApiErrorHandling(
            () => gmail.users.drafts.create({
                userId: 'me',
                requestBody: {
                    message: messageRequest
                }
            }),
            'Failed to create draft'
        );
        
        logger.info('Draft created successfully', { draftId: response.data.id });
        return response.data;
    } catch (error: any) {
        logger.error('Failed to create draft', { error: error.message });
        throw error;
    }
}

/**
 * Read an email message
 * @param messageId ID of the message to read
 * @returns Email message data
 */
export async function readEmail(messageId: string): Promise<any> {
    try {
        const gmail = getGmailClient();
        
        const response = await withApiErrorHandling(
            () => gmail.users.messages.get({
                userId: 'me',
                id: messageId,
                format: 'full'
            }),
            'Failed to read email'
        );
        
        const headers = response.data.payload?.headers || [];
        const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
        const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
        const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
        const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';
        const threadId = response.data.threadId || '';
        
        // Extract email content
        const { text, html } = extractEmailContent(response.data.payload as GmailMessagePart || {});
        
        // Use plain text content if available, otherwise use HTML content
        let body = text || html || '';
        
        // If we only have HTML content, add a note
        const contentTypeNote = !text && html ?
            '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';
        
        // Get attachment information
        const attachments: EmailAttachment[] = [];
        const processAttachmentParts = (part: GmailMessagePart, path: string = '') => {
            if (part.body && part.body.attachmentId) {
                const filename = part.filename || `attachment-${part.body.attachmentId}`;
                attachments.push({
                    id: part.body.attachmentId,
                    filename: filename,
                    mimeType: part.mimeType || 'application/octet-stream',
                    size: part.body.size || 0
                });
            }
            
            if (part.parts) {
                part.parts.forEach((subpart: GmailMessagePart) =>
                    processAttachmentParts(subpart, `${path}/parts`)
                );
            }
        };
        
        if (response.data.payload) {
            processAttachmentParts(response.data.payload as GmailMessagePart);
        }
        
        // Add attachment info to output if any are present
        const attachmentInfo = attachments.length > 0 ?
            `\n\nAttachments (${attachments.length}):\n` +
            attachments.map(a => `- ${a.filename} (${a.mimeType}, ${Math.round(a.size/1024)} KB)`).join('\n') : '';
        
        logger.info('Email read successfully', { messageId });
        return {
            id: messageId,
            threadId,
            subject,
            from,
            to,
            date,
            body: `${contentTypeNote}${body}${attachmentInfo}`,
            attachments
        };
    } catch (error: any) {
        logger.error('Failed to read email', { messageId, error: error.message });
        throw error;
    }
}

/**
 * Search for emails
 * @param query Gmail search query
 * @param maxResults Maximum number of results to return
 * @returns List of matching emails
 */
export async function searchEmails(query: string, maxResults: number = 10): Promise<any[]> {
    try {
        const gmail = getGmailClient();
        
        const response = await withApiErrorHandling(
            () => gmail.users.messages.list({
                userId: 'me',
                q: query,
                maxResults
            }),
            'Failed to search emails'
        );
        
        const messages = response.data.messages || [];
        const results = await Promise.all(
            messages.map(async (msg) => {
                const detail = await withApiErrorHandling(
                    () => gmail.users.messages.get({
                        userId: 'me',
                        id: msg.id!,
                        format: 'metadata',
                        metadataHeaders: ['Subject', 'From', 'Date']
                    }),
                    `Failed to get details for message ${msg.id}`
                );
                
                const headers = detail.data.payload?.headers || [];
                return {
                    id: msg.id,
                    subject: headers.find(h => h.name === 'Subject')?.value || '',
                    from: headers.find(h => h.name === 'From')?.value || '',
                    date: headers.find(h => h.name === 'Date')?.value || ''
                };
            })
        );
        
        logger.info('Email search completed', { query, resultCount: results.length });
        return results;
    } catch (error: any) {
        logger.error('Failed to search emails', { query, error: error.message });
        throw error;
    }
}

/**
 * Modify email labels
 * @param messageId ID of the message to modify
 * @param addLabelIds Labels to add
 * @param removeLabelIds Labels to remove
 * @returns Modified message
 */
export async function modifyEmail(messageId: string, addLabelIds?: string[], removeLabelIds?: string[]): Promise<any> {
    try {
        const gmail = getGmailClient();
        
        // Prepare request body
        const requestBody: any = {};
        
        if (addLabelIds && addLabelIds.length > 0) {
            requestBody.addLabelIds = addLabelIds;
        }
        
        if (removeLabelIds && removeLabelIds.length > 0) {
            requestBody.removeLabelIds = removeLabelIds;
        }
        
        const response = await withApiErrorHandling(
            () => gmail.users.messages.modify({
                userId: 'me',
                id: messageId,
                requestBody
            }),
            'Failed to modify email'
        );
        
        logger.info('Email modified successfully', { messageId });
        return response.data;
    } catch (error: any) {
        logger.error('Failed to modify email', { messageId, error: error.message });
        throw error;
    }
}

/**
 * Delete an email
 * @param messageId ID of the message to delete
 */
export async function deleteEmail(messageId: string): Promise<void> {
    try {
        const gmail = getGmailClient();
        
        await withApiErrorHandling(
            () => gmail.users.messages.delete({
                userId: 'me',
                id: messageId
            }),
            'Failed to delete email'
        );
        
        logger.info('Email deleted successfully', { messageId });
    } catch (error: any) {
        logger.error('Failed to delete email', { messageId, error: error.message });
        throw error;
    }
}

/**
 * Helper function to process operations in batches
 * @param items Items to process
 * @param batchSize Number of items to process in each batch
 * @param processFn Function to process a batch of items
 * @returns Results of processing
 */
export async function processBatches<T, U>(
    items: T[],
    batchSize: number,
    processFn: (batch: T[]) => Promise<U[]>
): Promise<{ successes: U[], failures: { item: T, error: Error }[] }> {
    const successes: U[] = [];
    const failures: { item: T, error: Error }[] = [];
    
    // Process in batches
    for (let i = 0; i < items.length; i += batchSize) {
        const batch = items.slice(i, i + batchSize);
        try {
            const results = await processFn(batch);
            successes.push(...results);
        } catch (error) {
            // If batch fails, try individual items
            for (const item of batch) {
                try {
                    const result = await processFn([item]);
                    successes.push(...result);
                } catch (itemError) {
                    failures.push({ item, error: itemError as Error });
                }
            }
        }
    }
    
    return { successes, failures };
}

/**
 * Validates an email for sending
 * @param emailData Email data to validate
 * @throws ValidationError if validation fails
 */
function validateEmail(emailData: any): void {
    // Helper function to validate an email address
    function checkEmail(email: string, fieldName: string): void {
        const result = validateEmailAddress(email);
        if (!result.valid) {
            throw new ValidationError(
                `Invalid ${fieldName} email address: ${email} - ${result.reason}`,
                { [fieldName]: [result.reason || 'Invalid email format'] }
            );
        }
    }
    
    // Validate 'to' addresses
    if (!emailData.to || !Array.isArray(emailData.to) || emailData.to.length === 0) {
        throw new ValidationError('At least one recipient is required', { 
            to: ['At least one recipient email address is required'] 
        });
    }
    
    for (const email of emailData.to) {
        checkEmail(email, 'to');
    }
    
    // Validate 'cc' addresses if present
    if (emailData.cc && emailData.cc.length > 0) {
        for (const email of emailData.cc) {
            checkEmail(email, 'cc');
        }
    }
    
    // Validate 'bcc' addresses if present
    if (emailData.bcc && emailData.bcc.length > 0) {
        for (const email of emailData.bcc) {
            checkEmail(email, 'bcc');
        }
    }
    
    // Validate subject
    if (!emailData.subject || emailData.subject.trim() === '') {
        throw new ValidationError('Email subject cannot be empty', 
            { subject: ['Subject is required'] }
        );
    }
    
    // Validate body
    if (!emailData.body) {
        throw new ValidationError('Email body cannot be empty', 
            { body: ['Body is required'] }
        );
    }
    
    // Validate body content
    if (typeof emailData.body === 'string') {
        const textResult = validateEmailContent(emailData.body, false);
        if (!textResult.valid) {
            throw new ValidationError(
                `Invalid email content: ${textResult.reason}`,
                { body: [textResult.reason || 'Invalid content'] }
            );
        }
    } else if (typeof emailData.body === 'object') {
        // Validate text content if present
        if (emailData.body.text) {
            const textResult = validateEmailContent(emailData.body.text, false);
            if (!textResult.valid) {
                throw new ValidationError(
                    `Invalid plain text content: ${textResult.reason}`,
                    { 'body.text': [textResult.reason || 'Invalid content'] }
                );
            }
        }
        
        // Validate HTML content if present
        if (emailData.body.html) {
            const htmlResult = validateEmailContent(emailData.body.html, true);
            if (!htmlResult.valid) {
                throw new ValidationError(
                    `Invalid HTML content: ${htmlResult.reason}`,
                    { 'body.html': [htmlResult.reason || 'Invalid content'] }
                );
            }
        }
        
        // Ensure at least one content type is provided
        if (!emailData.body.text && !emailData.body.html) {
            throw new ValidationError('Email must have content', {
                body: ['Either text or HTML content must be provided']
            });
        }
    } else {
        throw new ValidationError('Invalid body format', {
            body: ['Body must be a string or an object with text/html properties']
        });
    }
}
