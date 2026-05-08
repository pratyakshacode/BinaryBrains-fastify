import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Chapter } from "../../entities/Chapter";

export const updateChapter = async (req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    try {
        const { chapterId } = req.params as any;
        const { title, description, sectionIds } = req.body as any;

        const chapter = await Chapter.findOne({ where: { id: chapterId, isDeleted: false } });

        if (!chapter) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({ message: "Chapter not found." });
        }

        if (title) chapter.title = title;
        if (description !== undefined) chapter.description = description;
        
        // 🔥 This is where the dnd-kit sorting array is saved instantly!
        if (sectionIds && Array.isArray(sectionIds)) {
            chapter.sectionIds = sectionIds;
        }

        await chapter.save();
        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({ data: chapter });
    } catch (error) {
        logger.error("Error updating chapter:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ message: "Internal Server Error" });
    }
};