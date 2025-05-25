/**
 * Authentication module for Gmail MCP Server
 * Handles OAuth2 authentication with Google APIs
 */

import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import os from 'os';
import http from 'http';
import open from 'open';
import { AuthenticationError } from './error-handler.js';
import { logger } from './error-logger.js';

// Configuration paths
export const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
export const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
export const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');

// OAuth2 client instance
let oauth2Client: OAuth2Client;

/**
 * Loads API credentials and sets up OAuth2 client
 * @returns Configured OAuth2 client
 * @throws AuthenticationError if credentials cannot be loaded
 */
export async function loadCredentials(): Promise<OAuth2Client> {
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
export async function authenticate(): Promise<void> {
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

/**
 * Get the OAuth2 client
 * @returns OAuth2 client instance
 */
export function getOAuth2Client(): OAuth2Client {
    if (!oauth2Client) {
        throw new AuthenticationError('OAuth2 client not initialized. Call loadCredentials() first.');
    }
    return oauth2Client;
}
