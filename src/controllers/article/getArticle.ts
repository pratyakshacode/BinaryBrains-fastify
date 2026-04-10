import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { FindOneOptions } from "typeorm";
import { Article } from "../../entities/Article";
import { getSingleRecord } from "../../utils/sql/sqlUtils";
import { isInvalid } from "../../utils/util";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";

export const getArticle = async (req: FastifyRequest, reply: FastifyReply) => {
    try {

        const { articleId } = req.params as { articleId: string };

        logger.info("Fetching article with ID: ", articleId);

        const articleQuery: FindOneOptions<Article> = {
            where: { id: articleId }
        };

        const article = await getSingleRecord(Article, articleQuery);

        if(isInvalid(article)) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Article with given id not found."
            });
        }

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Article fetched successfully.",
            data: article
        });

    } catch (error) {

        logger.error("Error in getArticle", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An error occurred while fetching the article. Please try again later."
        });
        
    }
}