/**
 * Error logging utility for Gmail MCP Server
 * Provides centralized error logging with different severity levels
 */

// Log levels
export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  FATAL = 'FATAL'
}

interface LogMessage {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: Record<string, any>;
  error?: Error;
}

// Format log messages with colors and structured data
function formatLogMessage(logEntry: LogMessage): string {
  const { timestamp, level, message, context, error } = logEntry;
  
  // Color codes for different log levels
  const colors = {
    [LogLevel.DEBUG]: '\x1b[36m', // Cyan
    [LogLevel.INFO]: '\x1b[32m',  // Green
    [LogLevel.WARN]: '\x1b[33m',  // Yellow
    [LogLevel.ERROR]: '\x1b[31m', // Red
    [LogLevel.FATAL]: '\x1b[35m', // Magenta
  };
  
  const reset = '\x1b[0m';
  const colorCode = colors[level] || reset;
  
  let formattedMessage = `${colorCode}[${timestamp}] [${level}]${reset} ${message}`;
  
  if (context && Object.keys(context).length > 0) {
    formattedMessage += `\nContext: ${JSON.stringify(context, null, 2)}`;
  }
  
  if (error) {
    formattedMessage += `\nError: ${error.message}`;
    if (error.stack) {
      formattedMessage += `\nStack: ${error.stack}`;
    }
  }
  
  return formattedMessage;
}

/**
 * Logger class to handle all application logging
 */
export class Logger {
  private static instance: Logger;
  private minLevel: LogLevel = LogLevel.INFO;
  
  private constructor() {}
  
  /**
   * Get the singleton instance of the logger
   */
  public static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }
  
  /**
   * Set the minimum log level
   */
  public setMinLevel(level: LogLevel): void {
    this.minLevel = level;
  }
  
  /**
   * Get the current timestamp formatted for logging
   */
  private getTimestamp(): string {
    return new Date().toISOString();
  }
  
  /**
   * Log a message at the specified level
   */
  private log(level: LogLevel, message: string, context?: Record<string, any>, error?: Error): void {
    const logLevels = {
      [LogLevel.DEBUG]: 0,
      [LogLevel.INFO]: 1,
      [LogLevel.WARN]: 2,
      [LogLevel.ERROR]: 3,
      [LogLevel.FATAL]: 4,
    };
    
    if (logLevels[level] >= logLevels[this.minLevel]) {
      const logEntry: LogMessage = {
        timestamp: this.getTimestamp(),
        level,
        message,
        context,
        error,
      };
      
      console.log(formatLogMessage(logEntry));
    }
  }
  
  /**
   * Log debug message
   */
  public debug(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.DEBUG, message, context);
  }
  
  /**
   * Log info message
   */
  public info(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.INFO, message, context);
  }
  
  /**
   * Log warning message
   */
  public warn(message: string, context?: Record<string, any>, error?: Error): void {
    this.log(LogLevel.WARN, message, context, error);
  }
  
  /**
   * Log error message
   */
  public error(message: string, context?: Record<string, any>, error?: Error): void {
    this.log(LogLevel.ERROR, message, context, error);
  }
  
  /**
   * Log fatal error message
   */
  public fatal(message: string, context?: Record<string, any>, error?: Error): void {
    this.log(LogLevel.FATAL, message, context, error);
  }
}

// Export singleton instance
export const logger = Logger.getInstance();

/**
 * Error boundary for async functions
 * @param fn - Function to execute
 * @param logOptions - Logging options
 * @returns Result of the function execution
 */
export async function withErrorLogging<T>(
  fn: () => Promise<T>,
  logOptions: {
    operation: string;
    context?: Record<string, any>;
    onError?: (error: any) => void;
  }
): Promise<T> {
  try {
    logger.debug(`Starting: ${logOptions.operation}`, logOptions.context);
    const result = await fn();
    logger.debug(`Completed: ${logOptions.operation}`, logOptions.context);
    return result;
  } catch (error: any) {
    logger.error(`Failed: ${logOptions.operation}`, {
      ...logOptions.context,
      errorMessage: error.message,
    }, error);
    
    if (logOptions.onError) {
      logOptions.onError(error);
    }
    
    throw error;
  }
}
