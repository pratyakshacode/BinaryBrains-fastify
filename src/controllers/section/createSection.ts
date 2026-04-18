import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Section, SectionType } from "../../entities/Section";
import { isInvalid } from "../../utils/util";
import { createOneRecord } from "../../utils/sql/sqlUtils";

export const createSection = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        // 1. Added description to the expected payload
        const { title, description, type, isPublic } = req.body as { 
            title: string, 
            description?: string, // Make it optional
            type: string,         // Treat as raw string until validated
            isPublic?: boolean 
        };
        
        if (isInvalid(title) || isInvalid(type)) {
            logger.error("Title and type are not given in the request body.");
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Title and type are required to create a section."
            });
        }

        // 2. Strict Enum Validation (Runtime Safety)
        if (!Object.values(SectionType).includes(type as SectionType)) {
            logger.error(`Invalid section type provided: ${type}`);
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Invalid section type provided."
            });
        }

        logger.debug("Creating the section with:", { title, type });

        // 3. Added description to the creation payload
        const section = await createOneRecord(Section, {
            title, 
            description: description || "", // Default to empty string if missing
            type: type as SectionType,
            isPublic: isPublic !== undefined ? isPublic : false // Safer boolean check
        });

        logger.info("Section created successfully!");

        // 4. Perfect! This returns the ID the frontend needs for the batch mapping.
        return reply.status(HTTP_STATUS_CODE.CREATED).send({
            status: HTTP_STATUS_MESSAGES.CREATED,
            message: "Section created successfully!",
            data: section
        });

    } catch (error) {
        logger.error("Error in createSection", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Error in creating new section."
        });
    }
}