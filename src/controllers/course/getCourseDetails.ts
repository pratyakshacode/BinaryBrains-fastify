import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { isInvalid } from "../../utils/util";
import { getSingleRecord } from "../../utils/sql/sqlUtils";
import { FindOneOptions } from "typeorm";
import { Course } from "../../entities/Course";

export const getCourseDetails = async (req: FastifyRequest, reply: FastifyReply) => {
    try {   

        const { courseId } = (req.params as any);

        if(isInvalid(courseId)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Invalid course id found in request."
            });
        }

        const courseQuery: FindOneOptions<Course> = {
            where: {
                id: courseId
            }
        }

        const course = await getSingleRecord(Course, courseQuery);

        if(isInvalid(course)) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Course with given id not found."
            })
        }

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Course details fetched successfully!",
            data: course
        });

    } catch (error) {
        logger.error("Error in getCourseDetails", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Error in getting the details of course. Please contact admin!"
        })
    }
}