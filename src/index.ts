#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { google } from 'googleapis';
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import open from 'open';
import os from 'os';
import { createEmailMessage } from "./utl.js";
import { createLabel, updateLabel, deleteLabel, listLabels, findLabelByName, getOrCreateLabel, GmailLabel } from "./label-manager.js";
import { GmailApiError, AuthenticationError, ValidationError, RateLimitError } from "./error-handler.js";
import { logger } from "./error-logger.js";
import { validateEmail, validateEmailAddress, validateEmailContent } from "./email-validator.js";

// Set up global unhandled error handling
process.on('uncaughtException', (error) => {
    console.error('UNHANDLED EXCEPTION:', error);
    // Attempt to exit gracefully
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('UNHANDLED REJECTION:', reason);
    // Do not exit to allow potential recovery
});

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration paths
const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');

// Type definitions for Gmail API responses
interface GmailMessagePart {
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

interface EmailAttachment {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}

interface EmailContent {
    text: string;
    html: string;
}

// OAuth2 configuration
let oauth2Client: OAuth2Client;

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
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
 * Loads API credentials and sets up OAuth2 client
 * @returns Configured OAuth2 client
 * @throws AuthenticationError if credentials cannot be loaded
 */
async function loadCredentials() {
    try {
        logger.info('Loading API credentials');
        
        // Create config directory if it doesn't exist
        if (!process.env.GMAIL_OAUTH_PATH && !CREDENTIALS_PATH && !fs.existsSync(CONFIG_DIR)) {
            try {
                fs.mkdirSync(CONFIG_DIR, { recursive: true });
                logger.debug(`Created config directory: ${CONFIG_DIR}`);
            } catch (error: any) {
                throw new AuthenticationError(`Failed to create config directory: ${error.message}`);
            }
        }

        // Check for OAuth keys in current directory first, then in config directory
        const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');
        let oauthPath = OAUTH_PATH;

        if (fs.existsSync(localOAuthPath)) {
            try {
                // If found in current directory, copy to config directory
                fs.copyFileSync(localOAuthPath, OAUTH_PATH);
                logger.info('OAuth keys found in current directory, copied to global config.');
            } catch (error: any) {
                logger.warn(`Could not copy OAuth keys to config directory: ${error.message}`);
                // Continue using the local file
                oauthPath = localOAuthPath;
            }
        }

        if (!fs.existsSync(oauthPath)) {
            throw new AuthenticationError(
                `OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or ${CONFIG_DIR}`
            );
        }

        let keysContent;
        try {
            keysContent = JSON.parse(fs.readFileSync(oauthPath, 'utf8'));
        } catch (error: any) {
            throw new AuthenticationError(`Failed to parse OAuth keys file: ${error.message}`);
        }

        const keys = keysContent.installed || keysContent.web;

        if (!keys) {
            throw new AuthenticationError(
                'Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.'
            );
        }

        const callback = process.argv[2] === 'auth' && process.argv[3] 
            ? process.argv[3] 
            : "http://localhost:3000/oauth2callback";

        oauth2Client = new OAuth2Client(
            keys.client_id,
            keys.client_secret,
            callback
        );

        if (fs.existsSync(CREDENTIALS_PATH)) {
            try {
                const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
                oauth2Client.setCredentials(credentials);
                logger.info('Loaded existing OAuth credentials');
            } catch (error: any) {
                logger.warn(`Failed to load saved credentials: ${error.message}. Will need to re-authenticate.`);
                // We'll continue without credentials and authenticate later
            }
        } else {
            logger.info('No saved credentials found. Authentication will be required.');
        }
        
        return oauth2Client;
    } catch (error: any) {
        // Transform generic errors into authentication errors
        if (!(error instanceof AuthenticationError)) {
            error = new AuthenticationError(
                `Failed to load credentials: ${error.message || 'Unknown error'}`
            );
        }
        
        logger.error('Authentication error', { message: error.message }, error);
        throw error;
    }
}

/**
 * Handles the OAuth2 authentication flow with Google
 * @returns Promise that resolves when authentication is complete
 * @throws AuthenticationError if authentication fails
 */
async function authenticate() {
    logger.info('Starting authentication process');
    const server = http.createServer();
    
    try {
        server.listen(3000);
    } catch (error: any) {
        throw new AuthenticationError(
            `Failed to start authentication server: ${error.message}. ` +
            'Port 3000 might be in use by another application.'
        );
    }

    return new Promise<void>((resolve, reject) => {
        // Configure authentication timeout
        const timeout = setTimeout(() => {
            server.close();
            reject(new AuthenticationError('Authentication timed out after 5 minutes'));
        }, 5 * 60 * 1000); // 5 minute timeout

        try {
            const authUrl = oauth2Client.generateAuthUrl({
                access_type: 'offline',
                scope: ['https://www.googleapis.com/auth/gmail.modify'],
                prompt: 'consent' // Always ask for consent to ensure refresh token
            });

            logger.info('Authentication URL generated');
            console.log('Please visit this URL to authenticate:', authUrl);
            
            // Try to open the URL in the default browser
            open(authUrl).catch(error => {
                logger.warn(`Could not automatically open browser: ${error.message}`);
                console.log('Please manually copy and paste the URL into your browser.');
            });

            server.on('request', async (req, res) => {
                if (!req.url?.startsWith('/oauth2callback')) return;

                // Clear the timeout since we got a response
                clearTimeout(timeout);

                const url = new URL(req.url, 'http://localhost:3000');
                const code = url.searchParams.get('code');
                const error = url.searchParams.get('error');

                if (error) {
                    res.writeHead(400, {'Content-Type': 'text/html'});
                    res.end(`<html><body><h2>Authentication Error</h2><p>${error}</p></body></html>`);
                    server.close();
                    reject(new AuthenticationError(`OAuth error: ${error}`));
                    return;
                }

                if (!code) {
                    res.writeHead(400, {'Content-Type': 'text/html'});
                    res.end('<html><body><h2>Error</h2><p>No authorization code provided</p></body></html>');
                    server.close();
                    reject(new AuthenticationError('No authorization code provided'));
                    return;
                }

                try {
                    logger.debug('Exchanging authorization code for tokens');
                    const { tokens } = await oauth2Client.getToken(code);
                    
                    // Verify we got the required tokens
                    if (!tokens.access_token) {
                        throw new AuthenticationError('No access token received');
                    }
                    
                    oauth2Client.setCredentials(tokens);
                    
                    // Ensure credentials directory exists
                    if (!fs.existsSync(path.dirname(CREDENTIALS_PATH))) {
                        fs.mkdirSync(path.dirname(CREDENTIALS_PATH), { recursive: true });
                    }
                    
                    try {
                        fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens));
                        logger.info('Saved authentication tokens to disk');
                    } catch (error: any) {
                        logger.error(`Failed to save credentials: ${error.message}`);
                        // Continue anyway as we have credentials in memory
                    }

                    res.writeHead(200, {'Content-Type': 'text/html'});
                    res.end(`
                        <html>
                            <body>
                                <h2>Authentication Successful!</h2>
                                <p>You can close this window and return to the application.</p>
                            </body>
                        </html>
                    `);
                    server.close();
                    logger.info('Authentication completed successfully');
                    resolve();
                } catch (error: any) {
                    const errorMessage = error.message || 'Unknown error';
                    logger.error(`Authentication failed: ${errorMessage}`, { error });
                    
                    res.writeHead(500, {'Content-Type': 'text/html'});
                    res.end(`
                        <html>
                            <body>
                                <h2>Authentication Failed</h2>
                                <p>${errorMessage}</p>
                            </body>
                        </html>
                    `);
                    server.close();
                    reject(new AuthenticationError(
                        `Failed to obtain access token: ${errorMessage}`
                    ));
                }
            });
        } catch (error: any) {
            clearTimeout(timeout);
            server.close();
            logger.error('Authentication setup failed', { error });
            reject(new AuthenticationError(
                `Authentication setup failed: ${error.message || 'Unknown error'}`
            ));
        }
    });
}

// Schema definitions
const SendEmailSchema = z.object({
    to: z.array(z.string()).describe("List of recipient email addresses"),
    subject: z.string().describe("Email subject"),
    body: z.string().describe("Email body content (used for text/plain or when htmlBody not provided)"),
    htmlBody: z.string().optional().describe("HTML version of the email body"),
    mimeType: z.enum(['text/plain', 'text/html', 'multipart/alternative']).optional().default('text/plain').describe("Email content type"),
    cc: z.array(z.string()).optional().describe("List of CC recipients"),
    bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
    threadId: z.string().optional().describe("Thread ID to reply to"),
    inReplyTo: z.string().optional().describe("Message ID being replied to"),
});

const ReadEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to retrieve"),
});

const SearchEmailsSchema = z.object({
    query: z.string().describe("Gmail search query (e.g., 'from:example@gmail.com')"),
    maxResults: z.number().optional().describe("Maximum number of results to return"),
});

// Updated schema to include removeLabelIds
const ModifyEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to modify"),
    labelIds: z.array(z.string()).optional().describe("List of label IDs to apply"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to the message"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from the message"),
});

const DeleteEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to delete"),
});

// New schema for listing email labels
const ListEmailLabelsSchema = z.object({}).describe("Retrieves all available Gmail labels");

// Label management schemas
const CreateLabelSchema = z.object({
    name: z.string().describe("Name for the new label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Creates a new Gmail label");

const UpdateLabelSchema = z.object({
    id: z.string().describe("ID of the label to update"),
    name: z.string().optional().describe("New name for the label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Updates an existing Gmail label");

const DeleteLabelSchema = z.object({
    id: z.string().describe("ID of the label to delete"),
}).describe("Deletes a Gmail label");

const GetOrCreateLabelSchema = z.object({
    name: z.string().describe("Name of the label to get or create"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Gets an existing label by name or creates it if it doesn't exist");

// Schemas for batch operations
const BatchModifyEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to modify"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to all messages"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from all messages"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

const BatchDeleteEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to delete"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

/**
 * Helper function to wrap API calls with error handling
 * @param apiCall Function that makes the API call
 * @param errorMessage Message to use if the call fails
 * @returns Result of the API call
 */
async function withApiErrorHandling<T>(apiCall: () => Promise<T>, errorMessage: string): Promise<T> {
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
 * Main function to run the MCP server
 */
async function main() {
    try {
        logger.info('Starting Gmail MCP Server');
        
        // Load credentials with error handling
        await loadCredentials();

        // Handle authentication if requested
        if (process.argv[2] === 'auth') {
            await authenticate();
            logger.info('Authentication completed successfully');
            console.log('Authentication completed successfully');
            process.exit(0);
        }

        // Initialize Gmail API
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        logger.info('Gmail API initialized');

        // Server implementation
        const server = new Server({
            name: "gmail",
            version: "1.0.0",
            capabilities: {
                tools: {},
            },
        });
        
        logger.info('MCP Server created');
        
        // Tool handlers
        server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [
            {
                name: "send_email",
                description: "Sends a new email",
                inputSchema: zodToJsonSchema(SendEmailSchema),
            },
            {
                name: "draft_email",
                description: "Draft a new email",
                inputSchema: zodToJsonSchema(SendEmailSchema),
            },
            {
                name: "read_email",
                description: "Retrieves the content of a specific email",
                inputSchema: zodToJsonSchema(ReadEmailSchema),
            },
            {
                name: "search_emails",
                description: "Searches for emails using Gmail search syntax",
                inputSchema: zodToJsonSchema(SearchEmailsSchema),
            },
            {
                name: "modify_email",
                description: "Modifies email labels (move to different folders)",
                inputSchema: zodToJsonSchema(ModifyEmailSchema),
            },
            {
                name: "delete_email",
                description: "Permanently deletes an email",
                inputSchema: zodToJsonSchema(DeleteEmailSchema),
            },
            {
                name: "list_email_labels",
                description: "Retrieves all available Gmail labels",
                inputSchema: zodToJsonSchema(ListEmailLabelsSchema),
            },
            {
                name: "batch_modify_emails",
                description: "Modifies labels for multiple emails in batches",
                inputSchema: zodToJsonSchema(BatchModifyEmailsSchema),
            },
            {
                name: "batch_delete_emails",
                description: "Permanently deletes multiple emails in batches",
                inputSchema: zodToJsonSchema(BatchDeleteEmailsSchema),
            },
            {
                name: "create_label",
                description: "Creates a new Gmail label",
                inputSchema: zodToJsonSchema(CreateLabelSchema),
            },
            {
                name: "update_label",
                description: "Updates an existing Gmail label",
                inputSchema: zodToJsonSchema(UpdateLabelSchema),
            },
            {
                name: "delete_label",
                description: "Deletes a Gmail label",
                inputSchema: zodToJsonSchema(DeleteLabelSchema),
            },
            {
                name: "get_or_create_label",
                description: "Gets an existing label by name or creates it if it doesn't exist",
                inputSchema: zodToJsonSchema(GetOrCreateLabelSchema),
            },
        ],
    }))

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const { name, arguments: args } = request.params;

        /**
         * Handles sending or drafting an email with validation and error handling
         * @param action Action to perform: "send" or "draft"
         * @param validatedArgs Validated email arguments
         * @returns API response data
         */
        async function handleEmailAction(action: "send" | "draft", validatedArgs: any) {
            try {
                const { to, cc, bcc, subject, body, threadId } = validatedArgs;
                
                // Validate email addresses
                logger.debug('Validating email addresses');
                
                // Helper function to validate an email address
                // Use the imported validateEmailAddress function from email-validator.ts
                function checkEmail(email: string, fieldName: string): void {
                    // Import the function from email-validator.ts
                    const result = validateEmailAddress(email);
                    if (!result.valid) {
                        throw new ValidationError(
                            `Invalid ${fieldName} email address: ${email} - ${result.reason}`,
                            { [fieldName]: [result.reason || 'Invalid email format'] }
                        );
                    }
                }
                
                // Validate 'to' addresses
                for (const email of to) {
                    checkEmail(email, 'to');
                }
                
                // Validate 'cc' addresses if present
                if (cc && cc.length > 0) {
                    for (const email of cc) {
                        checkEmail(email, 'cc');
                    }
                }
                
                // Validate 'bcc' addresses if present
                if (bcc && bcc.length > 0) {
                    for (const email of bcc) {
                        checkEmail(email, 'bcc');
                    }
                }
                
                // Validate subject
                if (!subject || subject.trim() === '') {
                    throw new ValidationError('Email subject cannot be empty', 
                        { subject: ['Subject is required'] }
                    );
                }
                
                // Log information about the email being created
                logger.info(`Creating ${action === 'send' ? 'email' : 'draft'}`, { 
                    to: to.length, 
                    cc: cc?.length || 0, 
                    bcc: bcc?.length || 0,
                    hasThreadId: !!threadId
                });
                
                // Create the raw email message
                const message = await createEmailMessage({
                    to: to.join(','),
                    cc: cc ? cc.join(',') : undefined,
                    bcc: bcc ? bcc.join(',') : undefined,
                    subject,
                    text: typeof body === 'string' ? body : body.text,
                    html: typeof body === 'string' ? undefined : body.html
                });
                
                const encodedMessage = Buffer.from(message).toString('base64')
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');
                
                // Create message request object
                const messageRequest: { raw: string; threadId?: string } = {
                    raw: encodedMessage
                };
                
                // Add threadId if provided
                if (threadId) {
                    messageRequest.threadId = threadId;
                }
                
                try {
                    // Send or create draft based on action
                    if (action === "send") {
                        const response = await gmail.users.messages.send({
                            userId: 'me',
                            requestBody: messageRequest,
                        });
                        
                        logger.info('Email sent successfully', { messageId: response.data.id });
                        
                        return {
                            content: [{
                                type: "text",
                                text: `Email sent successfully with ID: ${response.data.id}`,
                            }],
                        };
                    } else {
                        const response = await gmail.users.drafts.create({
                            userId: 'me',
                            requestBody: {
                                message: messageRequest,
                            },
                        });
                        
                        logger.info('Email draft created successfully', { draftId: response.data.id });
                        
                        return {
                            content: [{
                                type: "text",
                                text: `Email draft created successfully with ID: ${response.data.id}`,
                            }],
                        };
                    }
                } catch (apiError: any) {
                    // Handle API-specific errors
                    logger.error(`Failed to ${action} email`, { error: apiError.message });
                    
                    if (apiError.code === 401 || apiError.code === 403) {
                        throw new AuthenticationError(`Authentication error: ${apiError.message}`);
                    }
                    
                    if (apiError.code === 429 || (apiError.message && apiError.message.includes('quota'))) {
                        throw new RateLimitError('Rate limit exceeded', 3600);
                    }
                    
                    throw new GmailApiError(
                        `Failed to ${action} email: ${apiError.message || 'Unknown error'}`,
                        apiError.code || 500,
                        apiError.errors?.[0]?.reason || 'api_error'
                    );
                }
            } catch (error: any) {
                // Create appropriate error response
                logger.error(`Email ${action} error`, { 
                    message: error.message,
                    errorType: error.constructor.name 
                });
                
                if (error instanceof ValidationError || 
                    error instanceof AuthenticationError || 
                    error instanceof GmailApiError || 
                    error instanceof RateLimitError) {
                    // Use our custom error types directly
                    return {
                        content: [{
                            type: "text",
                            text: `Error: ${error.message}`,
                        }],
                    };
                }
                
                // Generic error handling
                return {
                    content: [{
                        type: "text",
                        text: `Error ${action}ing email: ${error.message || 'Unknown error'}`,
                    }],
                };
            }
        } // End of handleEmailAction function

        // Helper function to process operations in batches
        async function processBatches<T, U>(
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

        try {
            switch (name) {
                case "send_email":
                case "draft_email": {
                    const validatedArgs = SendEmailSchema.parse(args);
                    const action = name === "send_email" ? "send" : "draft";
                    return await handleEmailAction(action, validatedArgs);
                }

                case "read_email": {
                    const validatedArgs = ReadEmailSchema.parse(args);
                    const response = await gmail.users.messages.get({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        format: 'full',
                    });

                    const headers = response.data.payload?.headers || [];
                    const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                    const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                    const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                    const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';
                    const threadId = response.data.threadId || '';

                    // Extract email content using the recursive function
                    const { text, html } = extractEmailContent(response.data.payload as GmailMessagePart || {});

                    // Use plain text content if available, otherwise use HTML content
                    // (optionally, you could implement HTML-to-text conversion here)
                    let body = text || html || '';

                    // If we only have HTML content, add a note for the user
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

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Thread ID: ${threadId}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}`,
                            },
                        ],
                    };
                }

                case "search_emails": {
                    const validatedArgs = SearchEmailsSchema.parse(args);
                    const response = await gmail.users.messages.list({
                        userId: 'me',
                        q: validatedArgs.query,
                        maxResults: validatedArgs.maxResults || 10,
                    });

                    const messages = response.data.messages || [];
                    const results = await Promise.all(
                        messages.map(async (msg) => {
                            const detail = await gmail.users.messages.get({
                                userId: 'me',
                                id: msg.id!,
                                format: 'metadata',
                                metadataHeaders: ['Subject', 'From', 'Date'],
                            });
                            const headers = detail.data.payload?.headers || [];
                            return {
                                id: msg.id,
                                subject: headers.find(h => h.name === 'Subject')?.value || '',
                                from: headers.find(h => h.name === 'From')?.value || '',
                                date: headers.find(h => h.name === 'Date')?.value || '',
                            };
                        })
                    );

                    return {
                        content: [
                            {
                                type: "text",
                                text: results.map(r =>
                                    `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`
                                ).join('\n'),
                            },
                        ],
                    };
                }

                // Updated implementation for the modify_email handler
                case "modify_email": {
                    const validatedArgs = ModifyEmailSchema.parse(args);
                    
                    // Prepare request body
                    const requestBody: any = {};
                    
                    if (validatedArgs.labelIds) {
                        requestBody.addLabelIds = validatedArgs.labelIds;
                    }
                    
                    if (validatedArgs.addLabelIds) {
                        requestBody.addLabelIds = validatedArgs.addLabelIds;
                    }
                    
                    if (validatedArgs.removeLabelIds) {
                        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }
                    
                    await gmail.users.messages.modify({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        requestBody: requestBody,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} labels updated successfully`,
                            },
                        ],
                    };
                }

                case "delete_email": {
                    const validatedArgs = DeleteEmailSchema.parse(args);
                    await gmail.users.messages.delete({
                        userId: 'me',
                        id: validatedArgs.messageId,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} deleted successfully`,
                            },
                        ],
                    };
                }

                case "list_email_labels": {
                    const labelResults = await listLabels(gmail);
                    const systemLabels = labelResults.system;
                    const userLabels = labelResults.user;

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n` +
                                    "System Labels:\n" +
                                    systemLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n') +
                                    "\nUser Labels:\n" +
                                    userLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n')
                            },
                        ],
                    };
                }

                case "batch_modify_emails": {
                    const validatedArgs = BatchModifyEmailsSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;
                    
                    // Prepare request body
                    const requestBody: any = {};
                    
                    if (validatedArgs.addLabelIds) {
                        requestBody.addLabelIds = validatedArgs.addLabelIds;
                    }
                    
                    if (validatedArgs.removeLabelIds) {
                        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }

                    // Process messages in batches
                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => {
                            const results = await Promise.all(
                                batch.map(async (messageId) => {
                                    const result = await gmail.users.messages.modify({
                                        userId: 'me',
                                        id: messageId,
                                        requestBody: requestBody,
                                    });
                                    return { messageId, success: true };
                                })
                            );
                            return results;
                        }
                    );

                    // Generate summary of the operation
                    const successCount = successes.length;
                    const failureCount = failures.length;
                    
                    let resultText = `Batch label modification complete.\n`;
                    resultText += `Successfully processed: ${successCount} messages\n`;
                    
                    if (failureCount > 0) {
                        resultText += `Failed to process: ${failureCount} messages\n\n`;
                        resultText += `Failed message IDs:\n`;
                        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: resultText,
                            },
                        ],
                    };
                }

                case "batch_delete_emails": {
                    const validatedArgs = BatchDeleteEmailsSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;

                    // Process messages in batches
                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => {
                            const results = await Promise.all(
                                batch.map(async (messageId) => {
                                    await gmail.users.messages.delete({
                                        userId: 'me',
                                        id: messageId,
                                    });
                                    return { messageId, success: true };
                                })
                            );
                            return results;
                        }
                    );

                    // Generate summary of the operation
                    const successCount = successes.length;
                    const failureCount = failures.length;
                    
                    let resultText = `Batch delete operation complete.\n`;
                    resultText += `Successfully deleted: ${successCount} messages\n`;
                    
                    if (failureCount > 0) {
                        resultText += `Failed to delete: ${failureCount} messages\n\n`;
                        resultText += `Failed message IDs:\n`;
                        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: resultText,
                            },
                        ],
                    };
                }

                // New label management handlers
                case "create_label": {
                    const validatedArgs = CreateLabelSchema.parse(args);
                    const result = await createLabel(gmail, validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }

                case "update_label": {
                    const validatedArgs = UpdateLabelSchema.parse(args);
                    
                    // Prepare request body with only the fields that were provided
                    const updates: any = {};
                    if (validatedArgs.name) updates.name = validatedArgs.name;
                    if (validatedArgs.messageListVisibility) updates.messageListVisibility = validatedArgs.messageListVisibility;
                    if (validatedArgs.labelListVisibility) updates.labelListVisibility = validatedArgs.labelListVisibility;
                    
                    const result = await updateLabel(gmail, validatedArgs.id, updates);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }

                case "delete_label": {
                    const validatedArgs = DeleteLabelSchema.parse(args);
                    const result = await deleteLabel(gmail, validatedArgs.id);

                    return {
                        content: [
                            {
                                type: "text",
                                text: result.message,
                            },
                        ],
                    };
                }

                case "get_or_create_label": {
                    const validatedArgs = GetOrCreateLabelSchema.parse(args);
                    const result = await getOrCreateLabel(gmail, validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility,
                    });

                    const action = result.type === 'user' && result.name === validatedArgs.name ? 'found existing' : 'created new';
                    
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Successfully ${action} label:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }

                default:
                    throw new Error(`Unknown tool: ${name}`);
            }
        } catch (error: any) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error: ${error.message}`,
                    },
                ],
            };
        }
    });

        const transport = new StdioServerTransport();
        server.connect(transport);
        
        logger.info('Server connected to transport and running');
    } catch (error: any) {
        // Handle different types of errors appropriately
        logger.error('Server initialization error', { 
            message: error.message, 
            stack: error.stack,
            errorType: error.constructor.name
        });
        
        // Different handling based on error type
        if (error instanceof AuthenticationError) {
            console.error('Authentication error:', error.message);
            console.log(`Status code: ${error.statusCode}`);
            console.log('Try running with the "auth" command to re-authenticate.');
        } else if (error instanceof GmailApiError) {
            console.error('Gmail API error:', error.message);
            console.log(`Status code: ${error.statusCode}, Error code: ${error.errorCode}`);
            if (error.requestId) {
                console.log(`Request ID: ${error.requestId}`);
            }
        } else if (error instanceof RateLimitError) {
            console.error('Rate limit exceeded:', error.message);
            if (error.retryAfter) {
                console.log(`Please try again after ${error.retryAfter} seconds.`);
            }
        } else if (error instanceof ValidationError) {
            console.error('Validation error:', error.message);
            if (Object.keys(error.fieldErrors).length > 0) {
                console.log('Field errors:');
                for (const [field, errors] of Object.entries(error.fieldErrors)) {
                    console.log(`  ${field}: ${errors.join(', ')}`);
                }
            }
        } else {
            console.error('Unexpected error:', error.message);
        }
        
        process.exit(1);
    }
}

main().catch((error) => {
    console.error('Server error:', error);
    process.exit(1);
});
