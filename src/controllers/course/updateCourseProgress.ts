import { FastifyReply, FastifyRequest } from "fastify";
import { In } from "typeorm";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Course } from "../../entities/Course";
import { CourseUserMap } from "../../entities/CourseUserMap";
import { SectionResourceMap } from "../../entities/SectionResourceMap";

interface ProgressPayload {
    resourceId: string;
}

export const updateCourseProgress = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        const { courseId } = req.params as { courseId: string };
        const { resourceId } = req.body as ProgressPayload;
        const userId = (req.user as any)?.id;

        if (!userId || !resourceId) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                message: "User ID and Resource ID are required."
            });
        }

        // 1. Fetch the user's enrollment record
        const enrollment: any = await CourseUserMap.findOne({
            where: { userId, courseId }
        });

        if (!enrollment) {
            return reply.status(HTTP_STATUS_CODE.FORBIDDEN).send({
                message: "User is not enrolled in this course."
            });
        }

        // 2. Initialize or update the completedResources array
        let completed = enrollment.completedResources || [];
        
        // If they already completed it, just return success (idempotent)
        if (completed.includes(resourceId)) {
            return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
                status: HTTP_STATUS_MESSAGES.SUCCESS,
                message: "Progress already recorded.",
                data: { progress: enrollment.progress }
            });
        }

        // Add the new resource
        completed.push(resourceId);

        // 3. Calculate the new total progress percentage
        // First, get all section IDs for this course
        const course = await Course.findOne({ where: { id: courseId }, select: ["curriculumTree"] });
        let totalResourcesInCourse = 0;

        if (course?.curriculumTree && Array.isArray(course.curriculumTree)) {
            const sectionIds: string[] = [];
            course.curriculumTree.forEach((chapter: any) => {
                if (chapter.sections) {
                    chapter.sections.forEach((sec: any) => sectionIds.push(sec.id));
                }
            });

            if (sectionIds.length > 0) {
                // Count how many total resources exist across all these sections
                totalResourcesInCourse = await SectionResourceMap.count({
                    where: { sectionId: In(sectionIds) }
                });
            }
        }

        // 4. Compute the percentage (Safeguard against division by zero)
        let newProgress = 0;
        if (totalResourcesInCourse > 0) {
            newProgress = Math.round((completed.length / totalResourcesInCourse) * 100);
            // Cap at 100 just in case
            newProgress = Math.min(newProgress, 100); 
        }

        // 5. Save the updated enrollment
        enrollment.completedResources = completed;
        enrollment.progress = newProgress;
        await enrollment.save();

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Progress updated successfully.",
            data: { 
                progress: newProgress,
                completedResources: completed
            }
        });

    } catch (error) {
        logger.error("Error updating course progress:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            message: "Failed to update course progress."
        });
    }
};