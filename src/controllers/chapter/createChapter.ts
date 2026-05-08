import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Chapter } from "../../entities/Chapter";
import { isInvalid } from "../../utils/util";
import { createOneRecord } from "../../utils/sql/sqlUtils";

// --- 1. CREATE CHAPTER ---
export const createChapter = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        const { title, description, isPublic } = req.body as any;
        const userId = (req.user as any)?.id || "admin-system";

        if (isInvalid(title)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ message: "Title is required." });
        }

        const chapterData = {
            title,
            description: description || "",
            isPublic: isPublic || false,
            sectionIds: [], // Initializes empty
            createdBy: userId as any
        };

        const chapter = await createOneRecord(Chapter, chapterData);

        logger.info(`Chapter created: ${chapter.id}`);

        return reply.status(HTTP_STATUS_CODE.CREATED).send({ 
            status: HTTP_STATUS_MESSAGES.CREATED,
            data: chapter 
        });

    } catch (error) {
        logger.error("Error creating chapter:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Internal Server Error" 
        });
    }
};