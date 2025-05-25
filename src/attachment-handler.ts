/**
 * Attachment handler module for Gmail MCP Server
 * Handles attachment processing and extraction
 */

import { getGmailClient } from './email-operations.js';
import { withApiErrorHandling } from './email-operations.js';
import { logger } from './error-logger.js';
import { ValidationError } from './error-handler.js';
import { GmailMessagePart } from './email-operations.js';

export interface AttachmentData {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
    data: Buffer;
}

/**
 * Extract attachments from a message
 * @param messagePart Message part to process
 * @returns List of attachment metadata
 */
export function extractAttachments(messagePart: GmailMessagePart): Array<{
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}> {
    const attachments: Array<{
        id: string;
        filename: string;
        mimeType: string;
        size: number;
    }> = [];

    // Process the current part
    if (messagePart.body && messagePart.body.attachmentId) {
        const filename = messagePart.filename || `attachment-${messagePart.body.attachmentId}`;
        attachments.push({
            id: messagePart.body.attachmentId,
            filename,
            mimeType: messagePart.mimeType || 'application/octet-stream',
            size: messagePart.body.size || 0
        });
    }

    // Recursively process child parts
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const childAttachments = extractAttachments(part);
            attachments.push(...childAttachments);
        }
    }

    return attachments;
}

/**
 * Get attachment data
 * @param messageId ID of the message containing the attachment
 * @param attachmentId ID of the attachment
 * @returns Attachment data including binary content
 */
export async function getAttachment(messageId: string, attachmentId: string): Promise<AttachmentData> {
    if (!messageId) {
        throw new ValidationError('Message ID cannot be empty', {
            messageId: ['Message ID is required']
        });
    }

    if (!attachmentId) {
        throw new ValidationError('Attachment ID cannot be empty', {
            attachmentId: ['Attachment ID is required']
        });
    }

    try {
        logger.debug('Getting attachment', { messageId, attachmentId });
        
        const gmail = getGmailClient();
        
        // Get attachment metadata first to get filename and MIME type
        const messageResponse = await withApiErrorHandling(
            () => gmail.users.messages.get({
                userId: 'me',
                id: messageId,
                format: 'full'
            }),
            `Failed to get message with ID ${messageId}`
        );
        
        // Find the attachment in the message parts
        let attachmentMeta: {
            filename: string;
            mimeType: string;
            size: number;
        } | undefined;
        
        function findAttachment(part: GmailMessagePart): boolean {
            if (part.body?.attachmentId === attachmentId) {
                attachmentMeta = {
                    filename: part.filename || `attachment-${attachmentId}`,
                    mimeType: part.mimeType || 'application/octet-stream',
                    size: part.body.size || 0
                };
                return true;
            }
            
            if (part.parts) {
                for (const childPart of part.parts) {
                    if (findAttachment(childPart)) {
                        return true;
                    }
                }
            }
            
            return false;
        }
        
        if (messageResponse.data.payload) {
            findAttachment(messageResponse.data.payload as GmailMessagePart);
        }
        
        if (!attachmentMeta) {
            throw new ValidationError('Attachment not found', {
                attachmentId: [`Attachment ${attachmentId} not found in message ${messageId}`]
            });
        }
        
        // Get attachment data
        const attachmentResponse = await withApiErrorHandling(
            () => gmail.users.messages.attachments.get({
                userId: 'me',
                messageId,
                id: attachmentId
            }),
            `Failed to get attachment with ID ${attachmentId}`
        );
        
        // Decode attachment data
        const data = Buffer.from(
            attachmentResponse.data.data || '',
            'base64'
        );
        
        logger.debug('Attachment retrieved successfully', {
            messageId,
            attachmentId,
            filename: attachmentMeta.filename,
            size: data.length
        });
        
        return {
            id: attachmentId,
            filename: attachmentMeta.filename,
            mimeType: attachmentMeta.mimeType,
            size: data.length,
            data
        };
    } catch (error: any) {
        logger.error('Failed to get attachment', { 
            messageId,
            attachmentId,
            error: error.message 
        });
        throw error;
    }
}

/**
 * Process attachments in a message
 * @param messageId ID of the message to process
 * @returns List of attachment metadata
 */
export async function processAttachments(messageId: string): Promise<Array<{
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}>> {
    try {
        const gmail = getGmailClient();
        
        // Get the message
        const response = await withApiErrorHandling(
            () => gmail.users.messages.get({
                userId: 'me',
                id: messageId,
                format: 'full'
            }),
            `Failed to get message with ID ${messageId}`
        );
        
        // Extract attachments
        const attachments = response.data.payload 
            ? extractAttachments(response.data.payload as GmailMessagePart)
            : [];
        
        logger.debug('Attachments processed', { 
            messageId, 
            attachmentCount: attachments.length 
        });
        
        return attachments;
    } catch (error: any) {
        logger.error('Failed to process attachments', { 
            messageId,
            error: error.message 
        });
        throw error;
    }
}
