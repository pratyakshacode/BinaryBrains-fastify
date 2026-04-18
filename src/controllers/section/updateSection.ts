import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { isInvalid } from "../../utils/util";
import { Section, SectionType } from "../../entities/Section";
import { deleteRecords, getSingleRecord, updateRecord } from "../../utils/sql/sqlUtils";
import { SectionResourceMap } from "../../entities/SectionResourceMap";
import { FindOneOptions, Not, In } from "typeorm";
import { AllowedResourcesBySectionType } from "../../config/section/sectionConfig";

export const updateSection = async (req: FastifyRequest, reply: FastifyReply) => {
    try {

        const { sectionId } = req.params as any;
        
        if(!sectionId) {
            logger.error("Section id is not given in the request params.");
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Section id is required to update the section."
            });
        }

        const sectionQuery: FindOneOptions<Section> = { where: { id: sectionId } };
        const existingSection: any = await getSingleRecord(Section, sectionQuery);

        if(isInvalid(existingSection)) {
            logger.error("Section with given id not found : " + sectionId);
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Section with given id not found."
            });
        }

        logger.info("Updating the section with id: ", sectionId);

        const updateData: any = {};
        const body = req.body as any;

        if(!isInvalid(body.title)) updateData['title'] = body.title;
        if(!isInvalid(body.isPublic)) updateData['isPublic'] = body.isPublic;

        if (!isInvalid(body.type) && Object.values(SectionType).includes(body.type)) {
            updateData.type = body.type;

            if (body.type !== existingSection.type) {
                logger.warn(`Section ${sectionId} type changed from ${existingSection.type} to ${body.type}. Pruning incompatible resources.`);
                
                // 1. Get the allowed resources for the NEW section type
                const allowedResources = AllowedResourcesBySectionType[body.type as SectionType];

                // 2. Perform the surgical deletion dynamically
                if (allowedResources && allowedResources.length > 0) {
                    await deleteRecords(SectionResourceMap, { 
                        sectionId, 
                        resourceType: Not(In(allowedResources)) // "Delete anything NOT IN this allowed list"
                    });
                } else {
                    // Edge Case: If a section type allows NO resources, wipe everything.
                    await deleteRecords(SectionResourceMap, { sectionId });
                }
            }
        }

        logger.debug("Updating the meta data of section with object : ", updateData);
        await updateRecord(Section, { id: sectionId }, updateData);

        logger.info("Section updated successfully!");
        
        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Section updated successfully!"
        });
        
    } catch (error) {
        logger.error("Error in updateSection", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Error in updating the section."
        });
    }
}