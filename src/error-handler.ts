/**
 * Error handling utilities for Gmail MCP Server
 * Provides consistent error handling patterns, custom error types,
 * and centralized error processing functionality.
 */

import { z } from "zod";
import type { ZodError } from "zod";

// Custom error types to differentiate between various error sources
export class GmailApiError extends Error {
  readonly statusCode: number;
  readonly errorCode: string;
  readonly requestId?: string;

  constructor(message: string, statusCode: number = 500, errorCode: string = 'gmail_api_error', requestId?: string) {
    super(message);
    this.name = 'GmailApiError';
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.requestId = requestId;
  }
}

export class AuthenticationError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode: number = 401) {
    super(message);
    this.name = 'AuthenticationError';
    this.statusCode = statusCode;
  }
}

export class ValidationError extends Error {
  readonly fieldErrors: Record<string, string[]>;

  constructor(message: string, fieldErrors: Record<string, string[]> = {}) {
    super(message);
    this.name = 'ValidationError';
    this.fieldErrors = fieldErrors;
  }
}

export class RateLimitError extends Error {
  readonly retryAfter?: number;

  constructor(message: string, retryAfter?: number) {
    super(message);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

// Helper to extract error details from Google API errors
export function parseGoogleApiError(error: any): GmailApiError {
  // Default values
  let message = 'An unknown error occurred with the Gmail API';
  let statusCode = 500;
  let errorCode = 'gmail_api_error';
  let requestId: string | undefined;

  if (error.response) {
    // Extract useful information from the error response
    const { data, status } = error.response;
    statusCode = status;
    
    // Try to get detailed error information
    if (data && data.error) {
      if (typeof data.error === 'string') {
        message = data.error;
      } else if (data.error.message) {
        message = data.error.message;
        errorCode = data.error.code || data.error.status || errorCode;
        requestId = data.error.requestId;
      }
    }
  } else if (error.message) {
    message = error.message;
  }

  return new GmailApiError(message, statusCode, errorCode, requestId);
}

// Helper to handle Zod validation errors
export function handleValidationError(error: z.ZodError): ValidationError {
  const fieldErrors: Record<string, string[]> = {};
  
  // Transform Zod errors into a more usable format
  for (const issue of error.errors) {
    const path = issue.path.join('.');
    if (!fieldErrors[path]) {
      fieldErrors[path] = [];
    }
    fieldErrors[path].push(issue.message);
  }
  
  return new ValidationError('Validation failed', fieldErrors);
}

// Function to create a standardized error response
export function createErrorResponse(error: Error): any {
  let response: any = {
    content: [
      {
        type: "text",
        text: `Error: ${error.message}`,
      },
    ],
  };

  // Add additional details based on error type
  if (error instanceof ValidationError && Object.keys(error.fieldErrors).length > 0) {
    // Include detailed validation errors
    const fieldErrorText = Object.entries(error.fieldErrors)
      .map(([field, messages]) => `  "${field}": ${messages.join(', ')}`)
      .join('\n');
    
    response.content[0].text += `\n\nValidation issues:\n${fieldErrorText}`;
  } else if (error instanceof GmailApiError) {
    // Include API error details
    response.content[0].text += `\nStatus Code: ${error.statusCode}`;
    response.content[0].text += `\nError Code: ${error.errorCode}`;
    
    if (error.requestId) {
      response.content[0].text += `\nRequest ID: ${error.requestId}`;
    }
  } else if (error instanceof RateLimitError && error.retryAfter) {
    // Include rate limit information
    response.content[0].text += `\nPlease retry after ${error.retryAfter} seconds.`;
  }

  return response;
}

// Unified error boundary for async functions
export async function withErrorBoundary<T>(fn: () => Promise<T>, errorTransformer?: (error: any) => Error): Promise<T> {
  try {
    return await fn();
  } catch (error: any) {
    // Transform the error if a transformer is provided
    if (errorTransformer) {
      throw errorTransformer(error);
    }

    // Handle specific error types
    if (error.code === 401 || error.code === 403 || error.message?.includes('authentication')) {
      throw new AuthenticationError(error.message || 'Authentication failed');
    }
    
    if (error.code === 429 || error.message?.includes('quota')) {
      const retryAfter = error.response?.headers?.['retry-after'] 
        ? parseInt(error.response.headers['retry-after'], 10) 
        : undefined;
      throw new RateLimitError(error.message || 'Rate limit exceeded', retryAfter);
    }

    if (error instanceof z.ZodError) {
      throw handleValidationError(error);
    }

    // For Google API errors
    if (error.response) {
      throw parseGoogleApiError(error);
    }

    // For any other errors
    throw error;
  }
}

// Email validation with better edge case handling
export function validateEmail(email: string): { valid: boolean; reason?: string } {
  // Simple regex validation for basic format
  const basicEmailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!basicEmailRegex.test(email)) {
    return { valid: false, reason: 'Invalid email format' };
  }

  // Advanced validation for edge cases
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

// Enhanced MIME type validation
export function validateMimeType(mimeType: string): { valid: boolean; reason?: string } {
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

// Content validation for email body
export function validateEmailContent(content: string, isHtml: boolean = false): { valid: boolean; reason?: string } {
  if (content === undefined || content === null) {
    return { valid: false, reason: 'Email content cannot be null or undefined' };
  }

  if (typeof content !== 'string') {
    return { valid: false, reason: 'Email content must be a string' };
  }

  if (content.length === 0) {
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
