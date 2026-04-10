import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Article } from "../../entities/Article";
import { createOneRecord, getSingleRecord } from "../../utils/sql/sqlUtils";
import { isInvalid } from "../../utils/util";
import { FindOneOptions } from "typeorm";

export const createArticle = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        
        const { title, description, content } = req.body as { title: string; description: string; content: string };

        if(isInvalid(title) || isInvalid(content)) {
            return reply.status(400).send({
                status: HTTP_STATUS_CODE.BAD_REQUEST,
                message: "Title and content are required fields."
            });
        }

        logger.info("Creating article with title: ", title);

        const articleQuery: FindOneOptions<Article> = {
            where: {
                title
            }
        }
        const articleExists = await getSingleRecord(Article, articleQuery);

        if (!isInvalid(articleExists)) {
            return reply.status(400).send({
                status: HTTP_STATUS_CODE.BAD_REQUEST,
                message: "An article with the same title already exists."
            });
        }

        const newArticle = await createOneRecord(Article, {
            title,
            description,
            content,
            createdBy: (req.user as JwtUser).id
        });
        
        return reply.status(HTTP_STATUS_CODE.CREATED).send({
            status: HTTP_STATUS_MESSAGES.CREATED,
            message: "Article created successfully.",
            data: newArticle
        });

    } catch (error) {
        
        logger.error("Error in createArticle", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, 
            message: "An error occurred while creating the article. Please try again later."
        });
    }
}