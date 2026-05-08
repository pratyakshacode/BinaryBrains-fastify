import { FastifyReply, FastifyRequest } from "fastify";
import { In, FindOneOptions } from "typeorm"; // 🔥 Don't forget to import 'In'
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { isInvalid } from "../../utils/util";
import { getSingleRecord } from "../../utils/sql/sqlUtils";
import { Course, CourseStatus } from "../../entities/Course";
import { CourseUserMap } from "../../entities/CourseUserMap";
import { SectionResourceMap } from "../../entities/SectionResourceMap"; // 🔥 Import the Map

export const getStudentCourseDetails = async (req: FastifyRequest, reply: FastifyReply) => {
    try {   
        const { courseId } = (req.params as any);
        const userId = (req.user as any)?.id; // Will be undefined for non-logged-in visitors

        if(isInvalid(courseId)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Invalid course id found in request."
            });
        }

        logger.info(`Fetching course details for courseId: ${courseId}`);

        const courseQuery: FindOneOptions<Course> = {
            where: {
                id: courseId,
                status: CourseStatus.PUBLISHED // Ensure students can only fetch published courses
            }
        }

        const course: any = await getSingleRecord(Course, courseQuery);

        if(isInvalid(course)) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Course with given id not found or is not published."
            })
        }

        if (course.curriculumTree && Array.isArray(course.curriculumTree)) {
            const sectionIds: string[] = [];
            
            // 1. Extract all section IDs
            course.curriculumTree.forEach((chapter: any) => {
                if (chapter.sections && Array.isArray(chapter.sections)) {
                    chapter.sections.forEach((sec: any) => {
                        if (sec.id) sectionIds.push(sec.id);
                    });
                }
            });

            if (sectionIds.length > 0) {
                // 2. Fetch resources for all sections at once (Ordered by drag-and-drop index)
                const mappedResources = await SectionResourceMap.find({
                    where: { sectionId: In(sectionIds) },
                    order: { orderIndex: 'ASC' }
                });

                // 3. Stitch resources back into the tree structure
                course.curriculumTree = course.curriculumTree.map((chapter: any) => ({
                    ...chapter,
                    sections: chapter.sections?.map((section: any) => ({
                        ...section,
                        resources: mappedResources
                            .filter(map => map.sectionId === section.id)
                            .map(map => ({
                                id: map.resourceId,
                                title: map.resourceTitle,
                                type: map.resourceType
                            }))
                    }))
                }));
            }
        }

        // --- ENROLLMENT CHECK LOGIC ---
        let isEnrolled = false;
        let enrollmentData = null;

        if (userId) {
            const enrollment = await CourseUserMap.findOne({
                where: { userId, courseId },
                select: ['id', 'progress', 'completedResources']
            });

            if (enrollment) {
                isEnrolled = true;
                enrollmentData = {
                    id: enrollment.id,
                    progress: enrollment.progress,
                    completedResources: enrollment.completedResources
                };
            }
        }

        // Attach the enrollment data to the course object
        const responseData = {
            ...course,
            isEnrolled,
            enrollment: enrollmentData
        };

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Course details fetched successfully!",
            data: responseData
        });

    } catch (error) {
        logger.error("Error in getStudentCourseDetails", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Error in getting the details of course. Please contact admin!"
        })
    }
}