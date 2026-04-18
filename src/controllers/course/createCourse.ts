import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Course, CourseType, CourseStatus } from "../../entities/Course";
import { isInvalid } from "../../utils/util";
import { createOneRecord } from "../../utils/sql/sqlUtils";

interface CreateCourseBody {
    title: string;
    description: string;
    type?: CourseType;
    amount?: number;
    tags?: string[];
}

export const createCourse = async (req: FastifyRequest, reply: FastifyReply) => {
    try {

        const { title, description, type, amount, tags } = req.body as CreateCourseBody;
        
        // Extract the user ID from your JWT middleware
        const userId = (req.user as JwtUser)?.id; 

        if(isInvalid(userId)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Invalid request found. Please login to create the course."
            })
        }

        logger.info(`Creating new course: ${title}`);

        if (isInvalid(title) || isInvalid(description)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Title and description are required."
            });
        }

        
        const newCourseData = {
            title,
            description,
            type: type || CourseType.FREE,
            amount: amount || 0,
            tags: tags || [],
            status: CourseStatus.DRAFT, // Always starts as a draft
            curriculumTree: [],         // Initializes empty
            instructors: [],            // Initializes empty
            createdBy: userId,
            updatedBy: userId
        };

        const newCourse = await createOneRecord(Course, newCourseData);

        logger.info(`Course created successfully with ID: ${newCourse.id}`);

        return reply.status(HTTP_STATUS_CODE.CREATED).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Course drafted successfully.",
            data: newCourse
        });

    } catch (error) {
        logger.error("Error in createCourse:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An error occurred while creating the course."
        });
    }
}