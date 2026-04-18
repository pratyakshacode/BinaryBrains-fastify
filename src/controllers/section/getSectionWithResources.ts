import { FastifyReply, FastifyRequest } from "fastify";
import { isInvalid } from "../../utils/util";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { FindOneOptions } from "typeorm";
import { Section } from "../../entities/Section";
import { getAllRecordsWithFilter, getSingleRecord } from "../../utils/sql/sqlUtils";
import { SectionResourceMap } from "../../entities/SectionResourceMap";
import { logger } from "../../utils/logger";

export const getSectionWithResources = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        
        const { sectionId } = req.params as any

        if(isInvalid(sectionId)) {
            logger.error("Section id is not given in the request params.")
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Section id is required to fetch section with resources."
            })
        }

        logger.info("Fetching the section with resources for section id : ", sectionId);

        const sectionQuery: FindOneOptions<Section> = {
            where: {
                id: sectionId
            },
            relations: {
                createdBy: true
            }
        }

        const section: any = await getSingleRecord(Section, sectionQuery);

        if(isInvalid(section)) {
            logger.error("No section found with the given id : ", sectionId);
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "No section found with the given id."
            })
        }

        logger.info("Section found successfully! Fetching the resources for the section.");
        const sectionResourceMapQuery = {
            where: {
                sectionId
            }
        }

        const resources = await getAllRecordsWithFilter(SectionResourceMap, sectionResourceMapQuery);
        
        const returnObject = {
            ...section,
            resources
        }

        logger.info("Section with resources fetched successfully!");
        
        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Section with resources fetched successfully!",
            data: returnObject
        });

    } catch (error) {

        logger.error("Error in getSectionWithResources", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An error occurred while fetching the section with resources."
        });
    }
}