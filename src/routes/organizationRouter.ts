/**
 * File contains the routes for creating, updating, and getting the organization.
 * Organization will be created in sql.
 */

import { FastifyInstance } from "fastify";
import { createOrganization } from "../controllers/organization/createOrganization";
import { authMiddleware } from "../middlewares/auth/authMiddleware";
import { getOrganizationById } from "../controllers/organization/getOrganizationById";
import { assignOwnerToOrganization } from "../controllers/organization/assignOwnerToOrganization";

export const organizationRouter = (fastify: FastifyInstance) => {

    // Run the authentication middleware before controller.
    fastify.addHook('preHandler', authMiddleware);

    fastify.get('/:organizationId', getOrganizationById);
    fastify.post('/', createOrganization);
    fastify.put('/', assignOwnerToOrganization);

}