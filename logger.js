const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const morgan = require('morgan');

const logger = winston.createLogger({
    level: 'debug',  // logging level
    format: winston.format.json(),  // log format, you can also use winston.format.simple() for a simpler format
    defaultMeta: { service: 'user-service' },  // default meta data added to each log
    transports: [
        // log to console
        new winston.transports.Console(),
        
        // log to a new file each day
        new DailyRotateFile({
            filename: 'logs/application-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
        }),
    ],
});

// Define a stream object to use with morgan
logger.stream = {
    // Use the log level 'info' with morgan
    write: (message) => logger.info(message),
};

logger.morgan = morgan;

module.exports = logger;
