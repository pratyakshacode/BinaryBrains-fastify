import { FastifyInstance } from "fastify";
import { authMiddleware } from "../../middlewares/auth/authMiddleware";
import { getAvailableResources } from "../../controllers/resources/getAvailableResources";

export const resourceRouter = async (fastify: FastifyInstance) => {

    fastify.addHook("preHandler", authMiddleware);

    // get available resources list
    fastify.get('/', getAvailableResources);
    
}