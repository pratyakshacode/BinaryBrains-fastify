/**
 * File contains the route for admin controls over the course to perform CRUD operations.
 */

import { FastifyInstance } from "fastify";
import { createCourse } from "../../controllers/course/createCourse";
import { authMiddleware } from "../../middlewares/auth/authMiddleware";

export const courseAdminRouter = (fastify: FastifyInstance) => {

    fastify.addHook('preHandler', authMiddleware);

    // course routes starts here.
    fastify.post('/', createCourse);
}