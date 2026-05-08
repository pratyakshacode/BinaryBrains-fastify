import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { CourseUserMap } from "../../entities/CourseUserMap";
import { Course, CourseType } from "../../entities/Course";
import { FindOneOptions } from "typeorm";
import { createOneRecord, getSingleRecord } from "../../utils/sql/sqlUtils";

export const enrollInCourse = async (req: FastifyRequest<{ Params: { courseId: string } }>, reply: FastifyReply) => {
    try {
        const { courseId } = req.params;
        const userId = (req.user as any)?.id; // Assuming you have JWT authentication middleware

        if (!userId) {
            return reply.status(HTTP_STATUS_CODE.UNAUTHORIZED).send({ 
                message: "You must be logged in to enroll." 
            });
        }

        logger.info(`User ${userId} attempting to enroll in course ${courseId}`);

        const query: FindOneOptions<Course> = {
            where: { id: courseId }
        }

        // 1. Verify the course exists and is published
        const course: Partial<Course> = await getSingleRecord(Course, query) as Course;
        
        if (!course || course.status !== 'published') {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({ 
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Course not found or is not available for enrollment." 
            });
        }

        const courseUserQuery: FindOneOptions<CourseUserMap> = {
            where: { userId, courseId }
        }
        
        // 2. Check if the user is already enrolled
        const existingEnrollment = await getSingleRecord(CourseUserMap, courseUserQuery);

        if (existingEnrollment) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "You are already enrolled in this course."
            });
        }

        // 3. Handle Free vs Paid Logic
        if (course.type === CourseType.PAID) {
            // ⚠️ TODO: Integrate Payment Gateway Here (Razorpay, Stripe, etc.)
            // For example:
            // 1. Verify payment signature from frontend
            // 2. If valid, proceed. If invalid, throw error.
            
            logger.info(`Processing payment logic for paid course: ${course.amount}`);
        }

        const enrollmentData = {
            userId,
            courseId,
            progress: 0,
            completedSections: []
        };

        // 4. Create the Enrollment Record
        const newEnrollment = await createOneRecord(CourseUserMap, enrollmentData);

        logger.info(`User ${userId} successfully enrolled in course ${courseId}`);

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Successfully enrolled in the course!",
            data: {
                enrollmentId: newEnrollment.id,
                courseId: newEnrollment.courseId
            }
        });

    } catch (error) {
        logger.error("Error enrolling in course:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            message: "An error occurred during enrollment."
        });
    }
}