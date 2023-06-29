const winston = require('winston');

const logger = winston.createLogger({
    level: 'debug',  // logging level
    format: winston.format.json(),  // log format, you can also use winston.format.simple() for a simpler format
    defaultMeta: { service: 'user-service' },  // default meta data added to each log
    transports: [
        new winston.transports.Console()  // log to console
    ]
});

module.exports = logger;

