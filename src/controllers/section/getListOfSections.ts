import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { isInvalid } from "../../utils/util";
import { Like } from "typeorm";
import { getFilteredRecordsWithPagination } from "../../utils/sql/sqlUtils";
import { Section } from "../../entities/Section";

export const getListOfSections = async (req: FastifyRequest, reply: FastifyReply) => {
    try {

        logger.info("Getting the list of sections ...");

        const page = parseInt((req.query as any).page || "1");
        const limit = parseInt((req.query as any).limit || "10");

        const title = (req.query as any).title;

        const query: any = {
            isDeleted: false
        }

        if(!isInvalid(title)) query['title'] = Like(`%${title}%`);

        const paginationOptions = {
            page, limit
        }
        
        logger.info("Calling the database with following options : ", paginationOptions, query);
        const data = await getFilteredRecordsWithPagination(Section, paginationOptions, query, { createdAt: "DESC" });

        logger.info("Section list fetched successfully!");
        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Section list fetched successfully.",
            data
        });
        
    } catch (error) {
        logger.error("Error in getListOfSections", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Error in getting list of sections"
        })
    }
}