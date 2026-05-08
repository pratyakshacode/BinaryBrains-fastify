import { FastifyInstance } from "fastify";
import { authMiddleware } from "../../middlewares/auth/authMiddleware";
import { getCoursesList } from "../../controllers/course/getCoursesList";
import { getCourseDetails } from "../../controllers/course/getCourseDetails";
import { enrollInCourse } from "../../controllers/course/enrolInCourse";
import { getStudentCourseDetails } from "../../controllers/course/getCourseDetailsForStudent";
import { getSecureResourceContent } from "../../controllers/resources/getSecureResourceContent";
import { evaluateSingleMcq } from "../../controllers/mcqs/evaluateSingleMcq";
import { updateCourseProgress } from "../../controllers/course/updateCourseProgress";

export const courseRouter = (fastify: FastifyInstance) => {

    fastify.addHook('preHandler', authMiddleware);

    // get list of courses with pagination and filters
    fastify.get('/', getCoursesList);

    // get details of course by course id
    fastify.get('/:courseId', getStudentCourseDetails);

    // get the resources linked to the course curriculum for student view
    fastify.get('/:courseId/resource', getSecureResourceContent);

    // enroll in a course
    fastify.post('/:courseId/enroll', enrollInCourse);

    // evaluate the mcq answer submitted by user for a resource linked to course curriculum.
    fastify.post("/:courseId/evaluate-mcq", evaluateSingleMcq);

    // course progress update route (for future use, not implemented yet)
    fastify.post('/:courseId/progress', updateCourseProgress);

}