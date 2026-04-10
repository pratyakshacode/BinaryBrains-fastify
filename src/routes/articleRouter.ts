/**
 * This file defines the routes for article-related operations in the Fastify application. It includes a route for creating a new article, which is protected by an authentication middleware to ensure that only authenticated users can access it. The createArticle controller handles the logic for creating a new article in the database.
 * Routes:
 * POST /article - Create a new article (requires authentication)
 * 
 * The request body for creating an article should include:
 * - title: string (required)
 * - description: string (optional)
 * - content: string (required)
 * 
 * The response will include the status of the operation and the created article data if successful.
 * 
 * Example request body for creating an article:
 * {
 *   "title": "My First Article",
 *   "description": "This is a description of my first article.",
 *   "content": "This is the content of my first article."
 * }
 */

import { FastifyInstance } from "fastify";
import { createArticle } from "../controllers/article/createArticle";
import { authMiddleware } from "../middlewares/auth/authMiddleware";
import { getArticle } from "../controllers/article/getArticle";
import { getAllArticles } from "../controllers/article/getAllArticles";

export const articleRouter = (fastify: FastifyInstance) => {

    // Middleware to check if the user is authenticated before allowing access to the article routes.
    fastify.addHook('preHandler', authMiddleware);

    /* ------------------------------------------------------------ */
    /* ------------------------- Article Routes ------------------------- */
    /* ------------------------------------------------------------ */

    // Route to get all articles with optional pagination and filtering.
    fastify.get('/', getAllArticles);
    
    // Route to get a single article by its ID.
    fastify.get('/:articleId', getArticle);

    // Route to create a new article. The request body should contain title, description, and content of the article.
    fastify.post('/', createArticle);
}