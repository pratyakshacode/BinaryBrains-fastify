import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";

// Import entities
import { Article } from "../../entities/Article";
import { Mcq } from "../../entities/MCQs";
import { CourseUserMap } from "../../entities/CourseUserMap";
import { Course } from "../../entities/Course";
import { SectionResourceMap } from "../../entities/SectionResourceMap";

interface GetResourceParams {
    courseId: string;
    sectionId: string;
    type: 'article' | 'mcq';
    id: string; // The resourceId
}

export const getSecureResourceContent = async (req: FastifyRequest<{ Params: GetResourceParams }>, reply: FastifyReply) => {
    try {
        const { courseId } = req.params;
        const { sectionId, type, id } = req.query as any;
        const userId = (req.user as any)?.id;

        if (!userId) {
            return reply.status(HTTP_STATUS_CODE.UNAUTHORIZED).send({ message: "Unauthorized." });
        }

        logger.info(`User ${userId} requesting resource ${id} from section ${sectionId} in course ${courseId}`);

        // --- SECURITY LAYER 1: ENROLLMENT CHECK ---
        const isEnrolled = await CourseUserMap.findOne({
            where: { userId, courseId }
        });

        if (!isEnrolled) {
            return reply.status(HTTP_STATUS_CODE.FORBIDDEN).send({
                message: "You must be enrolled in this course to view its content."
            });
        }

        // --- SECURITY LAYER 2: CURRICULUM TREE CHECK ---
        const course = await Course.findOne({ 
            where: { id: courseId }, 
            select: ['curriculumTree'] 
        });

        if (!course) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({ message: "Course not found." });
        }

        // Instantly verify if this sectionId exists ANYWHERE in this course's tree
        const isSectionInCourse = course.curriculumTree?.some(chapter => 
            chapter.sections?.some((sec: any) => sec.id === sectionId)
        );

        if (!isSectionInCourse) {
            logger.warn(`Section ${sectionId} does not belong to course ${courseId}`);
            return reply.status(HTTP_STATUS_CODE.FORBIDDEN).send({ message: "Invalid section for this course." });
        }

        // --- SECURITY LAYER 3: LINKAGE CHECK ---
        // Verify this specific resource actually lives inside this specific section
        const isResourceInSection = await SectionResourceMap.findOne({
            where: { sectionId, resourceId: id }
        });

        if (!isResourceInSection) {
            return reply.status(HTTP_STATUS_CODE.FORBIDDEN).send({ message: "This resource does not belong to the requested section." });
        }

        // --- FINAL STEP: FETCH THE CONTENT ---
        let resourceContent = null;

        switch (type) {
            case 'article':
                resourceContent = await Article.findOne({ where: { id } });
                break;
            case 'mcq':
                resourceContent = await Mcq.findOne({ where: { id } });
                break;
            default:
                return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ message: "Invalid resource type." });
        }

        if (!resourceContent) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({ message: "Content not found." });
        }

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Content fetched successfully.",
            data: {
                type,
                content: resourceContent
            }
        });

    } catch (error) {
        logger.error(`Error in getSecureResourceContent:`, error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            message: "An error occurred while validating and fetching the content."
        });
    }
};