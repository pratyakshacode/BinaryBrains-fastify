import { FastifyReply, FastifyRequest } from "fastify";
import { In, Not, Like } from "typeorm";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE } from "../../utils/httpUtils";
import { SectionResourceMap, ResourceType } from "../../entities/SectionResourceMap";

// Import your various resource entities here
import { Mcq } from "../../entities/MCQs"; 
import { Article } from "../../entities/Article"; 

export const getAvailableResources = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        const { type, sectionId, query } = req.query as any;

        if (!type || !sectionId) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ 
                message: "Type and sectionId are required parameters." 
            });
        }

        logger.info(`Searching available resources for Type: ${type}, Section: ${sectionId}`);

        // 1. Get IDs of resources already linked to this section to exclude them
        const linkedMaps = await SectionResourceMap.find({
            where: { sectionId, resourceType: type as ResourceType },
            select: ["resourceId"]
        });
        const excludedIds = linkedMaps.map(m => m.resourceId);

        // 2. Determine which Entity to query based on the type
        let entity: any;
        switch (type) {
            case ResourceType.MCQ: entity = Mcq; break;
            case ResourceType.ARTICLE: entity = Article; break;
            default:
                return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ message: "Invalid resource type." });
        }

        // 3. Build the find options
        const findOptions: any = {
            where: {
                isDeleted: false,
                // If there are excluded IDs, ensure they aren't in the result
                ...(excludedIds.length > 0 && { id: Not(In(excludedIds)) }),
                // If the user provided a search query
                ...(query && { title: Like(`%${query}%`) })
            },
            take: 20, // Limit results for performance
            order: { createdAt: "DESC" }
        };

        const results = await entity.find(findOptions);

        // 4. Normalize the data for the Dual-Listbox UI
        // This ensures the frontend always gets { id, title, type } regardless of the table
        const normalizedResources = results.map((item: any) => ({
            id: item.id,
            title: item.title, // Ensure your entities have a 'title' field or map it here
            type: type
        }));

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            data: normalizedResources
        });

    } catch (error) {
        logger.error("Error in getAvailableResources:", error);
        return reply.status(500).send({ message: "Internal Server Error" });
    }
};