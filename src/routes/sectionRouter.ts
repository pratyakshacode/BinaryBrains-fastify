import { FastifyInstance } from "fastify";
import { logger } from "../utils/logger";
import { authMiddleware } from "../middlewares/auth/authMiddleware";
import { getSectionWithResources } from "../controllers/section/getSectionWithResources";
import { getListOfSections } from "../controllers/section/getListOfSections";
import { createSection } from "../controllers/section/createSection";
import { updateSection } from "../controllers/section/updateSection";
import { deleteSection } from "../controllers/section/deleteSection";
import { getPublicSectionsWithResources } from "../controllers/section/getPublicSectionsWithResources";

export const sectionRouter = async (fastify: FastifyInstance) => {
    
    fastify.addHook("preHandler", authMiddleware);

    // Get list of sections
    fastify.get('/', getListOfSections);

    // Get list of public sections with resources.
    fastify.get('/public', getPublicSectionsWithResources);

    // Get the section with resources linked to section
    fastify.get('/:sectionId', getSectionWithResources);

    // create new section
    fastify.post("/", createSection);

    // update existing section with resources
    fastify.put("/:sectionId", updateSection);

    // delete existing section with resources mapping.
    fastify.delete("/:sectionId", deleteSection);

    
}