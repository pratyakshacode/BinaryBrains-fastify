import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { FindManyOptions, In } from "typeorm";
import { Section } from "../../entities/Section";
import { SectionResourceMap, ResourceType } from "../../entities/SectionResourceMap";
import { Mcq } from "../../entities/MCQs";
import { getAllRecordsWithFilter } from "../../utils/sql/sqlUtils";
// import { Article } from "../../entities/Article"; // Import future entities here

export const getPublicSectionsWithResources = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        const type = (req.query as any).type; 

        logger.info(`Fetching public sections of type: ${type || 'ORDINARY'}`);

        const sectionQuery: any = {
            where: {
                isDeleted: false,
                isPublic: true
            }
        }

        if (type) sectionQuery.where['type'] = type;

        const sections:any = await getAllRecordsWithFilter(Section, sectionQuery);

        if (Array.isArray(sections) && sections?.length === 0) {
            return reply.status(HTTP_STATUS_CODE.SUCCESS).send({ status: HTTP_STATUS_MESSAGES.SUCCESS, data: [] });
        }

        // 2. Fetch all mappings for these sections, preserving order
        const sectionIds = sections.map((s: any )=> s.id);

        const mappings = await SectionResourceMap.find({
            where: { sectionId: In(sectionIds) },
            order: { orderIndex: "ASC" } 
        });

        // 3. Generic Resource Fetching: Group IDs by their ResourceType
        const resourceIdsByType: Record<string, string[]> = {};
        mappings.forEach(m => {
            if (!resourceIdsByType[m.resourceType]) resourceIdsByType[m.resourceType] = [];
            resourceIdsByType[m.resourceType].push(m.resourceId);
        });

        // 4. Fetch data dynamically and store in a single Dictionary
        const resourceDictionary: Record<string, any> = {};

        for (const [resType, ids] of Object.entries(resourceIdsByType)) {
            if (ids.length === 0) continue;

            if (resType === ResourceType.MCQ) {
                const mcqs = await Mcq.find({
                    where: { id: In(ids), isDeleted: false },
                    select: ["id", "title", "type", "options"] // Safe fields only
                });
                // Tag the data with its type so the frontend knows how to render it
                mcqs.forEach(q => resourceDictionary[q.id] = { ...q, resourceType: resType });
            }
            
            // Easily scale this as your app grows!
            // else if (resType === ResourceType.ARTICLE) {
            //     const articles = await Article.find({ where: { id: In(ids), isDeleted: false }});
            //     articles.forEach(a => resourceDictionary[a.id] = { ...a, resourceType: resType });
            // }
        }

        // 5. Stitch resources back into their parent sections in the exact order
        const formattedData = sections.map((section: any) => {
            const sectionMappings = mappings.filter(m => m.sectionId === section.id);
            
            const resources = sectionMappings.map(mapping => {
                return resourceDictionary[mapping.resourceId] || null;
            }).filter(Boolean); // Removes nulls if a mapped resource was deleted

            return {
                ...section,
                resources
            };
        });

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            data: formattedData
        });

    } catch (error) {
        logger.error("Error in getPublicSectionsWithResources:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Failed to fetch sections and resources."
        });
    }
}