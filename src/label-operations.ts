/**
 * Label operations module for Gmail MCP Server
 * Handles creating, updating, deleting, and listing Gmail labels
 */

import { gmail_v1 } from 'googleapis';
import { GmailApiError, ValidationError } from './error-handler.js';
import { logger } from './error-logger.js';
import { withApiErrorHandling } from './email-operations.js';
import { getGmailClient } from './email-operations.js';

export interface GmailLabel {
    id: string;
    name: string;
    type: string;
    messageListVisibility?: string;
    labelListVisibility?: string;
}

/**
 * Create a new Gmail label
 * @param name Name of the label
 * @param options Label options
 * @returns Created label
 */
export async function createLabel(
    name: string, 
    options: { 
        messageListVisibility?: 'show' | 'hide',
        labelListVisibility?: 'labelShow' | 'labelShowIfUnread' | 'labelHide'
    } = {}
): Promise<GmailLabel> {
    if (!name || name.trim() === '') {
        throw new ValidationError('Label name cannot be empty', {
            name: ['Name is required']
        });
    }

    try {
        const gmail = getGmailClient();
        
        const requestBody: gmail_v1.Params$Resource$Users$Labels$Create = {
            name: name,
            messageListVisibility: options.messageListVisibility,
            labelListVisibility: options.labelListVisibility
        };
        
        const response = await withApiErrorHandling(
            () => gmail.users.labels.create({
                userId: 'me',
                requestBody: requestBody as any
            }),
            'Failed to create label'
        );
        
        logger.info('Label created successfully', { 
            labelId: response.data.id,
            labelName: response.data.name 
        });
        
        return {
            id: response.data.id!,
            name: response.data.name!,
            type: response.data.type!,
            messageListVisibility: response.data.messageListVisibility!,
            labelListVisibility: response.data.labelListVisibility!
        };
    } catch (error: any) {
        logger.error('Failed to create label', { 
            labelName: name,
            error: error.message 
        });
        throw error;
    }
}

/**
 * Update an existing Gmail label
 * @param id ID of the label to update
 * @param updates Label updates
 * @returns Updated label
 */
export async function updateLabel(
    id: string,
    updates: {
        name?: string,
        messageListVisibility?: 'show' | 'hide',
        labelListVisibility?: 'labelShow' | 'labelShowIfUnread' | 'labelHide'
    }
): Promise<GmailLabel> {
    if (!id) {
        throw new ValidationError('Label ID cannot be empty', {
            id: ['Label ID is required']
        });
    }

    if (Object.keys(updates).length === 0) {
        throw new ValidationError('No updates provided', {
            updates: ['At least one update is required']
        });
    }

    try {
        const gmail = getGmailClient();
        
        // First get the current label to ensure it exists
        const currentLabel = await withApiErrorHandling(
            () => gmail.users.labels.get({
                userId: 'me',
                id: id
            }),
            `Failed to get label with ID ${id}`
        );
        
        // Prepare request body with updates
        const requestBody: gmail_v1.Params$Resource$Users$Labels$Patch = {
            ...updates
        };
        
        const response = await withApiErrorHandling(
            () => gmail.users.labels.patch({
                userId: 'me',
                id: id,
                requestBody: requestBody as any
            }),
            'Failed to update label'
        );
        
        logger.info('Label updated successfully', { 
            labelId: response.data.id,
            labelName: response.data.name 
        });
        
        return {
            id: response.data.id!,
            name: response.data.name!,
            type: response.data.type!,
            messageListVisibility: response.data.messageListVisibility!,
            labelListVisibility: response.data.labelListVisibility!
        };
    } catch (error: any) {
        logger.error('Failed to update label', { 
            labelId: id,
            error: error.message 
        });
        throw error;
    }
}

/**
 * Delete a Gmail label
 * @param id ID of the label to delete
 */
export async function deleteLabel(id: string): Promise<{ message: string }> {
    if (!id) {
        throw new ValidationError('Label ID cannot be empty', {
            id: ['Label ID is required']
        });
    }

    try {
        const gmail = getGmailClient();
        
        // First get the label to ensure it exists and to capture its name for logging
        const labelResponse = await withApiErrorHandling(
            () => gmail.users.labels.get({
                userId: 'me',
                id: id
            }),
            `Failed to get label with ID ${id}`
        );
        
        const labelName = labelResponse.data.name;
        
        await withApiErrorHandling(
            () => gmail.users.labels.delete({
                userId: 'me',
                id: id
            }),
            'Failed to delete label'
        );
        
        logger.info('Label deleted successfully', { 
            labelId: id,
            labelName: labelName 
        });
        
        return { message: `Label '${labelName}' deleted successfully` };
    } catch (error: any) {
        logger.error('Failed to delete label', { 
            labelId: id,
            error: error.message 
        });
        throw error;
    }
}

/**
 * List all Gmail labels
 * @returns List of labels
 */
export async function listLabels(): Promise<GmailLabel[]> {
    try {
        const gmail = getGmailClient();
        
        const response = await withApiErrorHandling(
            () => gmail.users.labels.list({
                userId: 'me'
            }),
            'Failed to list labels'
        );
        
        const labels = response.data.labels || [];
        const formattedLabels = labels.map(label => ({
            id: label.id!,
            name: label.name!,
            type: label.type!,
            messageListVisibility: label.messageListVisibility!,
            labelListVisibility: label.labelListVisibility!
        }));
        
        logger.info('Labels listed successfully', { 
            labelCount: formattedLabels.length 
        });
        
        return formattedLabels;
    } catch (error: any) {
        logger.error('Failed to list labels', { 
            error: error.message 
        });
        throw error;
    }
}

/**
 * Find a label by name
 * @param name Name of the label to find
 * @returns Label if found, null otherwise
 */
export async function findLabelByName(name: string): Promise<GmailLabel | null> {
    if (!name) {
        throw new ValidationError('Label name cannot be empty', {
            name: ['Name is required']
        });
    }

    try {
        const labels = await listLabels();
        const label = labels.find(label => label.name === name);
        
        if (label) {
            logger.debug('Label found', { 
                labelId: label.id,
                labelName: label.name 
            });
            return label;
        }
        
        logger.debug('Label not found', { 
            labelName: name 
        });
        return null;
    } catch (error: any) {
        logger.error('Failed to find label by name', { 
            labelName: name,
            error: error.message 
        });
        throw error;
    }
}

/**
 * Get a label by name or create it if it doesn't exist
 * @param name Name of the label
 * @param options Label options if it needs to be created
 * @returns Label
 */
export async function getOrCreateLabel(
    name: string,
    options: { 
        messageListVisibility?: 'show' | 'hide',
        labelListVisibility?: 'labelShow' | 'labelShowIfUnread' | 'labelHide'
    } = {}
): Promise<GmailLabel> {
    try {
        // First try to find the label
        const existingLabel = await findLabelByName(name);
        
        if (existingLabel) {
            logger.debug('Using existing label', { 
                labelId: existingLabel.id,
                labelName: existingLabel.name 
            });
            return existingLabel;
        }
        
        // Create the label if it doesn't exist
        logger.debug('Creating new label', { 
            labelName: name 
        });
        return await createLabel(name, options);
    } catch (error: any) {
        logger.error('Failed to get or create label', { 
            labelName: name,
            error: error.message 
        });
        throw error;
    }
}
