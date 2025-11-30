/**
 * File contains the code to connect the typeorm with mysql connection
 */

import "reflect-metadata";
import { DataSource } from "typeorm";
import dotenv from 'dotenv';
import { FastifyInstance } from "fastify";
import { logger } from "../utils/logger";

dotenv.config();

// export const AppDataSource = new DataSource({
//   type: "mysql",
//   host: process.env.MYSQL_HOST,
//   port: parseInt(process.env.MYSQL_PORT),
//   username: 'root',
//   password: process.env.MYSQL_PASSWORD,
//   database: process.env.MYSQL_DATABASE,
//   synchronize: true,
//   logging: true,
//   entities: [__dirname + "/../entities/**/*.js"],
// });

// It can also be used1 in place of the above code in the case we have the url

export const AppDataSource = new DataSource({
  type: "mysql",
  url: process.env.MYSQL_URL,
  synchronize: true,
  logging: true,
  entities: [__dirname + "/../entities/**/*.js"],
});

export const connectDB = async (fastify: FastifyInstance) => {
  try {
    await Promise.all([
      AppDataSource.initialize().then(() => {
        logger.info("MySql connected successfully!");
      }),
    ]);
  } catch (error) {
    logger.error("ERROR IN CONNECTING DATABASES:", error);
    process.exit(1);
  }
};