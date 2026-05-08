import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Course } from "../../entities/Course";
import { FindOneOptions } from "typeorm";
import { getSingleRecord, updateRecord } from "../../utils/sql/sqlUtils";
import { isInvalid } from "../../utils/util";

interface UpdateCurriculumBody {
    curriculumTree: any[];
}

export const updateCourseCurriculum = async (req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    try {

        const courseId = (req.params as any).courseId ;
        const { curriculumTree } = req.body as UpdateCurriculumBody;

        // Extract the user ID from your JWT middleware
        const userId = (req.user as any)?.id || "admin-system"; 

        logger.info(`Updating curriculum tree for course: ${courseId}`);

        if (!Array.isArray(curriculumTree)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Curriculum tree must be a valid array."
            });
        }

        const courseQuery: FindOneOptions<Course> = {
            where: { id : courseId }
        }
        const course = await getSingleRecord(Course, courseQuery);

        if (isInvalid(course)) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Course not found."
            });
        }
        
        await updateRecord(Course, { id: courseId }, { curriculumTree, updatedBy: userId });

        logger.info(`Curriculum updated successfully for course: ${courseId}`);

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Curriculum saved successfully.",
        });

    } catch (error) {
        logger.error("Error in updateCurriculum:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An error occurred while saving the curriculum."
        });
    }
}