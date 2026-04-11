import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { FindOneOptions } from "typeorm";
import { Article } from "../../entities/Article";
import { isInvalid } from "../../utils/util";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { getSingleRecord } from "../../utils/sql/sqlUtils";

export const updateArticle = async (req: FastifyRequest, reply: FastifyReply) => {
    try {

        const articelId = (req.params as any).articleId;

        const { title, description, content } = req.body as { title: string; description: string; content: string };

        if(isInvalid(articelId)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Article ID is required to update article."
            });
        }

        if(isInvalid(title) || isInvalid(content) || isInvalid(description)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Title, content, and description are required fields."
            });
        }

        logger.info("Updating article with id: ", articelId);

        const articleQuery: FindOneOptions<Article> = {
            where: {
                id: articelId
            }
        }

        const article: any = await getSingleRecord(Article, articleQuery);

        if (isInvalid(article)) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Article not found."
            });
        }

        article.title = title;
        article.description = description;
        article.content = content;

        await article.save();
        
        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Article updated successfully.",
            data: article
        });
        
    } catch (error) {
        logger.error("Error in udpateArticle", error);
        return reply.status(500).send({ 
            status: "error", 
            message: "An error occurred while updating the article. Please try again later."
        });
    }
}