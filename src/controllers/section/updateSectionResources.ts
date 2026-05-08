// src/controllers/section.controller.ts

import { FastifyReply, FastifyRequest } from "fastify";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { logger } from "../../utils/logger";
import { SectionResourceMap, ResourceType } from "../../entities/SectionResourceMap";
import { Section } from "../../entities/Section";
import { User } from "../../entities/User"; // Assuming you need this for updatedBy

interface UpdateSectionResourcesBody {
    resources: {
        resourceId: string;
        resourceTitle: string;
        resourceType: ResourceType;
    }[];
}

export const updateSectionResources = async (req: FastifyRequest<{ Params: { sectionId: string }, Body: UpdateSectionResourcesBody }>, reply: FastifyReply) => {
    try {
        const { sectionId } = req.params;
        const { resources } = req.body;
        const userId = (req.user as any)?.id || "admin-system";

        logger.info(`Updating resources for section: ${sectionId}`);

        // 1. Verify the section exists
        const section = await Section.findOne({ where: { id: sectionId } });
        if (!section) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({ message: "Section not found." });
        }

        // 2. The "Delete & Re-insert" Strategy
        // First, wipe the existing layout for this section
        await SectionResourceMap.delete({ sectionId });

        // 3. Prepare the new layout payload with the updated orderIndex
        if (resources && resources.length > 0) {
            const newMaps = resources.map((res, index) => {
                return SectionResourceMap.create({
                    sectionId,
                    resourceId: res.resourceId,
                    resourceTitle: res.resourceTitle,
                    resourceType: res.resourceType,
                    orderIndex: index, // 🔥 The array index becomes the new database order!
                    createdBy: { id: userId } as User,
                    updatedBy: { id: userId } as User
                });
            });

            // Bulk insert the new perfectly-ordered rows
            await SectionResourceMap.save(newMaps);
        }

        // Update the section's timestamp to reflect activity
        section.updatedAt = new Date();
        await section.save();

        logger.info(`Successfully updated resources for section: ${sectionId}`);

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Section layout saved successfully."
        });

    } catch (error) {
        logger.error("Error updating section resources:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            message: "Internal Server Error" 
        });
    }
}