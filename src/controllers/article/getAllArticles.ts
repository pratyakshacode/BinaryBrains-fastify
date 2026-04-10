import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { getFilteredRecordsWithPagination } from "../../utils/sql/sqlUtils";
import { Article } from "../../entities/Article";
import { FindOneOptions, Like } from "typeorm";
import { isInvalid } from "../../utils/util";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";

export const getAllArticles = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        
        logger.info("Fetching all articles");

        const page = parseInt((req.query as any).page) || 1;
        const limit = parseInt((req.query as any).limit) || 10;

        const title = (req.query as any).title || "";

        const articleQuery: any = {}

        if(!isInvalid(title)) {
            articleQuery.title = Like(`%${title}%`);
        }

        const articles = await getFilteredRecordsWithPagination(Article, { page, limit }, articleQuery, { createdAt: "DESC" });

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Articles fetched successfully.",
            data: articles
        });

    } catch (error) {
        logger.error("Error in getAllArticles", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, 
            message: "An error occurred while fetching articles. Please try again later."
        });
    }
}