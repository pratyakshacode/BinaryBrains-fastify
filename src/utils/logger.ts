/**
 * Logger utility using log4js (TypeScript version)
 */

import log4js, { Logger } from 'log4js';

/**
 * Configure log4js
 */
log4js.configure({
  appenders: {
    everything: {
      type: 'stdout',
      layout: {
        type: 'pattern',
        pattern: '[%d] [%p] - %c - %f{1}:%l:%o - %m%n',
      },
    },
  },
  categories: {
    default: {
      appenders: ['everything'],
      level: "info" ,
      enableCallStack: true,
    },
  },
});

/**
 * Get logger by name
 * @param name Logger category name
 * @returns Logger instance
 */
export const getLoggerByName = (name: string): Logger =>
  log4js.getLogger(name);

/**
 * Default logger named "CPT"
 */
export const logger: Logger = getLoggerByName('CPT');