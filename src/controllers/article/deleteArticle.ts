import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { isInvalid } from "../../utils/util";
import { FindOneOptions } from "typeorm";
import { Article } from "../../entities/Article";
import { getSingleRecord } from "../../utils/sql/sqlUtils";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";

export const deleteArticle = async (req: FastifyRequest, reply: FastifyReply) => {
    try {

        const articleId = (req.params as any).articleId;
        
        if(isInvalid(articleId)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Article ID is required to delete article."
            });
        }

        const articleQuery: FindOneOptions<Article> = {
            where: {
                id: articleId
            }
        }

        const article: any = await getSingleRecord(Article, articleQuery);

        if (isInvalid(article)) {
            return reply.status(404).send({
                status: "error",
                message: "Article not found."
            });
        }

        article.isDeleted = true;
        
        await article.save();

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Article deleted successfully."
        })

    } catch (error) {
        logger.error("Error in deleteArticle", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, 
            message: "An error occurred while deleting the article. Please try again later."
        });
    }
}