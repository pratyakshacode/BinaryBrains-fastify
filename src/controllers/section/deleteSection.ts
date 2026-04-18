import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Section } from "../../entities/Section";
import { SectionResourceMap } from "../../entities/SectionResourceMap";
import { deleteRecords, getSingleRecord, updateRecord } from "../../utils/sql/sqlUtils";
import { FindOneOptions } from "typeorm";

export const deleteSection = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        const { sectionId } = req.params as any;
        
        if (!sectionId) {
            logger.error("Section id is not given in the request params.");
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Section id is required to delete the section."
            });
        }

        logger.info(`Attempting to delete section with id: ${sectionId}`);

        // 1. Verify the section exists and isn't already deleted
        const sectionQuery: FindOneOptions<Section> = { 
            where: { id: sectionId, isDeleted: false } 
        };
        
        const existingSection = await getSingleRecord(Section, sectionQuery);

        if (!existingSection) {
            logger.warn(`Section with id ${sectionId} not found or already deleted.`);
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Section with given id not found."
            });
        }

        // 2. Wipe all the mappings to clean up the junction table
        // This physically removes the rows from SectionResourceMap so no resources are orphaned
        await deleteRecords(SectionResourceMap, { sectionId });

        // 3. Soft Delete the actual Section
        // We keep the section row for analytics/history, but mark it as deleted
        await updateRecord(Section, { id: sectionId }, { isDeleted: true });

        logger.info(`Section ${sectionId} and all its resource mappings successfully deleted.`);
        
        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Section successfully deleted!"
        });

    } catch (error) {
        logger.error("Error in deleteSection", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An unexpected error occurred while deleting the section."
        });
    }
};