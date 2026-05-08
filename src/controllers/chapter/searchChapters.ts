import { FastifyReply, FastifyRequest } from "fastify";
import { Chapter } from "../../models/chapter/chapterModel";
import { Like } from "typeorm";
import { HTTP_STATUS_CODE } from "../../utils/httpUtils";
import { logger } from "../../utils/logger";

export const searchChapters = async (req: FastifyRequest<{ Querystring: { q: string } }>, reply: FastifyReply) => {
    try {
        const query = req.query.q || "";

        // Find up to 10 chapters matching the search string
        const chapters = await Chapter.find({
            where: { 
                title: Like(`%${query}%`),
                isDeleted: false 
            },
            take: 10,
            order: { createdAt: "DESC" }
        });

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({ data: chapters });
        
    } catch (error) {
        logger.error("Error searching chapters:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ message: "Internal Server Error" });
    }
};