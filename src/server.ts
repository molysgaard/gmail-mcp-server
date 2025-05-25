/**
 * Server module for Gmail MCP Server
 * Handles MCP server setup, tool registration, and request handling
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { logger } from "./error-logger.js";
import { 
    sendEmail, 
    createDraft, 
    readEmail, 
    searchEmails, 
    modifyEmail, 
    deleteEmail, 
    processBatches 
} from "./email-operations.js";
import { 
    createLabel, 
    updateLabel, 
    deleteLabel, 
    listLabels, 
    getOrCreateLabel 
} from "./label-operations.js";

// Schema definitions
const SendEmailSchema = z.object({
    to: z.array(z.string()).describe("List of recipient email addresses"),
    subject: z.string().describe("Email subject"),
    body: z.union([
        z.string().describe("Plain text content of the email"),
        z.object({
            text: z.string().optional().describe("Plain text content of the email"),
            html: z.string().optional().describe("HTML content of the email"),
        }).describe("Email content with optional text and HTML versions"),
    ]).describe("Email content, either as plain text or with text and HTML versions"),
    cc: z.array(z.string()).optional().describe("List of CC email addresses"),
    bcc: z.array(z.string()).optional().describe("List of BCC email addresses"),
    threadId: z.string().optional().describe("Thread ID to add the email to"),
});

const ReadEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to retrieve"),
});

const SearchEmailsSchema = z.object({
    query: z.string().describe("Gmail search query (e.g., 'from:example@gmail.com')"),
    maxResults: z.number().optional().describe("Maximum number of results to return"),
});

const ModifyEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to modify"),
    labelIds: z.array(z.string()).optional().describe("List of label IDs to apply"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to the message"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from the message"),
});

const DeleteEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to delete"),
});

const ListEmailLabelsSchema = z.object({}).describe("Retrieves all available Gmail labels");

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
 * Create and configure the MCP server
 * @returns Configured MCP server
 */
export function createServer(): Server {
    logger.info('Creating MCP server');
    
    const server = new Server({
        name: "gmail",
        version: "1.0.0",
        capabilities: {
            tools: {},
        },
    });
    
    // Register tool handlers
    registerToolHandlers(server);
    
    return server;
}

/**
 * Connect the server to a transport
 * @param server MCP server to connect
 */
export function connectServer(server: Server): void {
    logger.info('Connecting server to transport');
    const transport = new StdioServerTransport();
    server.connect(transport);
    logger.info('Server connected to transport');
}

/**
 * Register tool handlers with the server
 * @param server MCP server to register handlers with
 */
function registerToolHandlers(server: Server): void {
    // Register ListTools handler
    server.setRequestHandler(ListToolsRequestSchema, async () => {
        logger.debug('Handling ListTools request');
        
        return {
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
        };
    });
    
    // Register CallTool handler
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const { name, arguments: args } = request.params;
        logger.debug('Handling CallTool request', { toolName: name });
        
        try {
            switch (name) {
                case "send_email": {
                    const validatedArgs = SendEmailSchema.parse(args);
                    const result = await sendEmail(validatedArgs);
                    return {
                        content: [{
                            type: "text",
                            text: `Email sent successfully with ID: ${result.id}`
                        }]
                    };
                }
                
                case "draft_email": {
                    const validatedArgs = SendEmailSchema.parse(args);
                    const result = await createDraft(validatedArgs);
                    return {
                        content: [{
                            type: "text",
                            text: `Email draft created successfully with ID: ${result.id}`
                        }]
                    };
                }
                
                case "read_email": {
                    const validatedArgs = ReadEmailSchema.parse(args);
                    const result = await readEmail(validatedArgs.messageId);
                    return {
                        content: [{
                            type: "text",
                            text: `Thread ID: ${result.threadId}\nSubject: ${result.subject}\nFrom: ${result.from}\nTo: ${result.to}\nDate: ${result.date}\n\n${result.body}`
                        }]
                    };
                }
                
                case "search_emails": {
                    const validatedArgs = SearchEmailsSchema.parse(args);
                    const results = await searchEmails(validatedArgs.query, validatedArgs.maxResults);
                    return {
                        content: [{
                            type: "text",
                            text: results.map(r => 
                                `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`
                            ).join('\n')
                        }]
                    };
                }
                
                case "modify_email": {
                    const validatedArgs = ModifyEmailSchema.parse(args);
                    await modifyEmail(
                        validatedArgs.messageId, 
                        validatedArgs.addLabelIds || validatedArgs.labelIds, 
                        validatedArgs.removeLabelIds
                    );
                    return {
                        content: [{
                            type: "text",
                            text: `Email ${validatedArgs.messageId} labels updated successfully`
                        }]
                    };
                }
                
                case "delete_email": {
                    const validatedArgs = DeleteEmailSchema.parse(args);
                    await deleteEmail(validatedArgs.messageId);
                    return {
                        content: [{
                            type: "text",
                            text: `Email ${validatedArgs.messageId} deleted successfully`
                        }]
                    };
                }
                
                case "list_email_labels": {
                    const labels = await listLabels();
                    const labelText = labels.map(label => 
                        `ID: ${label.id}\nName: ${label.name}\nType: ${label.type}\n`
                    ).join('\n');
                    return {
                        content: [{
                            type: "text",
                            text: labelText || "No labels found"
                        }]
                    };
                }
                
                case "batch_modify_emails": {
                    const validatedArgs = BatchModifyEmailsSchema.parse(args);
                    const batchSize = validatedArgs.batchSize || 50;
                    
                    const { successes, failures } = await processBatches(
                        validatedArgs.messageIds,
                        batchSize,
                        async (batch) => {
                            const results = [];
                            for (const messageId of batch) {
                                await modifyEmail(
                                    messageId,
                                    validatedArgs.addLabelIds,
                                    validatedArgs.removeLabelIds
                                );
                                results.push(messageId);
                            }
                            return results;
                        }
                    );
                    
                    let message = `Modified ${successes.length} messages successfully.`;
                    if (failures.length > 0) {
                        message += ` Failed to modify ${failures.length} messages.`;
                    }
                    
                    return {
                        content: [{
                            type: "text",
                            text: message
                        }]
                    };
                }
                
                case "batch_delete_emails": {
                    const validatedArgs = BatchDeleteEmailsSchema.parse(args);
                    const batchSize = validatedArgs.batchSize || 50;
                    
                    const { successes, failures } = await processBatches(
                        validatedArgs.messageIds,
                        batchSize,
                        async (batch) => {
                            const results = [];
                            for (const messageId of batch) {
                                await deleteEmail(messageId);
                                results.push(messageId);
                            }
                            return results;
                        }
                    );
                    
                    let message = `Deleted ${successes.length} messages successfully.`;
                    if (failures.length > 0) {
                        message += ` Failed to delete ${failures.length} messages.`;
                    }
                    
                    return {
                        content: [{
                            type: "text",
                            text: message
                        }]
                    };
                }
                
                case "create_label": {
                    const validatedArgs = CreateLabelSchema.parse(args);
                    const result = await createLabel(validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility
                    });
                    return {
                        content: [{
                            type: "text",
                            text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`
                        }]
                    };
                }
                
                case "update_label": {
                    const validatedArgs = UpdateLabelSchema.parse(args);
                    const updates: any = {};
                    if (validatedArgs.name) updates.name = validatedArgs.name;
                    if (validatedArgs.messageListVisibility) updates.messageListVisibility = validatedArgs.messageListVisibility;
                    if (validatedArgs.labelListVisibility) updates.labelListVisibility = validatedArgs.labelListVisibility;
                    
                    const result = await updateLabel(validatedArgs.id, updates);
                    return {
                        content: [{
                            type: "text",
                            text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`
                        }]
                    };
                }
                
                case "delete_label": {
                    const validatedArgs = DeleteLabelSchema.parse(args);
                    const result = await deleteLabel(validatedArgs.id);
                    return {
                        content: [{
                            type: "text",
                            text: result.message
                        }]
                    };
                }
                
                case "get_or_create_label": {
                    const validatedArgs = GetOrCreateLabelSchema.parse(args);
                    const result = await getOrCreateLabel(validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility
                    });
                    
                    const action = result.type === 'user' && result.name === validatedArgs.name ? 'found existing' : 'created new';
                    
                    return {
                        content: [{
                            type: "text",
                            text: `Successfully ${action} label:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`
                        }]
                    };
                }
                
                default:
                    throw new Error(`Unknown tool: ${name}`);
            }
        } catch (error: any) {
            logger.error('Error handling tool call', { 
                toolName: name, 
                error: error.message 
            });
            
            return {
                content: [{
                    type: "text",
                    text: `Error: ${error.message}`
                }]
            };
        }
    });
    
    logger.debug('Tool handlers registered');
}
