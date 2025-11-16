import { FastifyInstance } from "fastify";

let logger: FastifyInstance['log'] | null = null;

// Initialization function for logger
export function initLogger(fastify: FastifyInstance) {
  logger = fastify.log;
}

// Getter to safely access logger anywhere
export function getLogger() {
  if (!logger) {
    return console;
  }
  return logger;
}