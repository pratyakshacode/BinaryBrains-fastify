import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Like, In, FindManyOptions } from "typeorm"; // 🔥 Imported In
import { getAllRecords, getAllRecordsWithFilter, getFilteredRecordsWithPagination } from "../../utils/sql/sqlUtils";
import { Mcq } from "../../entities/MCQs";
import { ResourceType, SectionResourceMap } from "../../entities/SectionResourceMap"; // 🔥 Imported Mapping

export const getListOfMcq = async (req: FastifyRequest, reply: FastifyReply) => {
    try {   
        logger.info("Fetching list of MCQs");

        const page = parseInt((req.query as any).page) || 1;
        const limit = parseInt((req.query as any).limit) || 10;
        const title = (req.query as any).title || "";
        
        const sectionId = (req.query as any).sectionId; 
        const forPlayer = (req.user as JwtUser).role === 'student';

        const mcqQuery = { isDeleted: false } as any;
        
        if (title) {
            mcqQuery.title = Like(`%${title}%`);
        }

        if (sectionId) {

            const mappingQuery: FindManyOptions<SectionResourceMap> = {
                where: {
                    sectionId: sectionId, resourceType: ResourceType.MCQ
                }
            }

            const mappings: SectionResourceMap[] = await getAllRecordsWithFilter(SectionResourceMap, mappingQuery) as SectionResourceMap[]

            if (mappings.length === 0) {
                // If the section is empty, return an empty pagination object instantly
                return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
                    status: HTTP_STATUS_MESSAGES.SUCCESS,
                    data: { records: [], pagination: { totalRecords: 0, totalPages: 0, page, limit } }
                });
            }

            // Extract IDs and add them to the main query
            const resourceIds = mappings.map(m => m.resourceId);
            mcqQuery.id = In(resourceIds); 
        }

        const paginationOptions = { page, limit };
        const orderBy = { createdAt: "DESC" };

        let select = ["id", "title", "type", "options"];
        
        if (!forPlayer) {
            // Admin gets everything. Students (forPlayer=true) do NOT get explanations or correct answers.
            select.push("explanation", "createdAt"); // Add correctAnswer here if your DB stores it!
        }

        logger.info("Querying MCQs with pagination:", paginationOptions, "and filters:", mcqQuery);
        
        const mcqsList = await getFilteredRecordsWithPagination(
            Mcq, 
            paginationOptions, 
            mcqQuery, 
            orderBy, 
            select
        );

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            data: mcqsList
        });

    } catch (error) {
        logger.error("Error in getListOfMcq:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An error occurred while fetching the list of MCQs."
         });
    }
}