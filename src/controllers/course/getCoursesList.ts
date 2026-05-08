import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { getFilteredRecordsWithPagination } from "../../utils/sql/sqlUtils";
import { Course } from "../../entities/Course";
import { Like } from "typeorm";

export const getCoursesList = async (request: FastifyRequest, reply: FastifyReply) => {
    try {
        const { query } = request as unknown as { query: Record<string, string | undefined> };
        const userId = (request.user as any)?.id;

        const title = query.title;
        const page = query.page ? parseInt(query.page) : 1;
        const limit = query.limit ? parseInt(query.limit) : 12; 
        const courseType = query.type;
        const status = query.status; 
        const archived = query.archived;
        
        // 🔥 NEW: Extract category from query
        const category = query.category;

        const filters: Record<string, any> = {};

        if (title) filters.title = Like(`%${title}%`);
        if (courseType) filters.type = courseType;
        if (status) filters.status = status;
        
        // 🔥 NEW: Filter by tags if a category is provided
        if (category) {
            filters.tags = Like(`%${category}%`);
        }
        
        if (archived !== undefined) {
            filters.archived = archived === 'true';
        } else {
            filters.archived = false; 
        }

        const courses: any = await getFilteredRecordsWithPagination(Course, { page, limit }, filters, { createdAt: "DESC" });

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            data: courses
        });

    } catch (error) {
        logger.error("Error in getting course list: ", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            message: "An error occurred while fetching the course list."
        });
    }
}