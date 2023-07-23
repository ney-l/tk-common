import winston from 'winston';
import BrowserConsole from 'winston-transport-browserconsole';

const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue',
};

winston.addColors(colors);

const getLogLevel = () => {
  switch (process.env.NODE_ENV) {
    case 'production':
      return 'error';

    case 'test':
      return 'none';

    default:
      return 'debug';
  }
};
const level = getLogLevel();

// Create a Winston logger instance
const logger = winston.createLogger({
  level,
  transports: [new BrowserConsole()],
  format: winston.format.combine(
    winston.format.colorize({ all: true }),
    winston.format.timestamp(),
    winston.format.printf(({ message }: { message: string }) => {
      const date = new Date();
      const formattedDate = new Intl.DateTimeFormat('en-DE', {
        dateStyle: 'short',
        timeStyle: 'long',
      }).format(date);

      return `[${formattedDate}] ${level.toUpperCase()}: ${message}`;
    })
  ),
});

export default logger;
