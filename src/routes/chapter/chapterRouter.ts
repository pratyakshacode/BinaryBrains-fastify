import { FastifyInstance } from "fastify";
import { authMiddleware } from "../../middlewares/auth/authMiddleware";
import { createChapter } from "../../controllers/chapter/createChapter";
import { searchChapters } from "../../controllers/chapter/searchChapters";
import { updateChapter } from "../../controllers/chapter/updateChapter";

export const chapterRouter = (fastify: FastifyInstance) => {

    fastify.addHook('preHandler', authMiddleware);

    fastify.get('/', searchChapters,);
    fastify.post('/', createChapter);
    fastify.put('/:chapterId', updateChapter);
}