/**
 * File contains the route for admin controls over the course to perform CRUD operations.
 */

import { FastifyInstance } from "fastify";
import { createCourse } from "../../controllers/course/createCourse";
import { authMiddleware } from "../../middlewares/auth/authMiddleware";
import { getCourseDetails } from "../../controllers/course/getCourseDetails";
import { updateCourseCurriculum } from "../../controllers/course/updateCourseCurriculum";
import { getCoursesList } from "../../controllers/course/getCoursesList";

export const courseAdminRouter = (fastify: FastifyInstance) => {

    fastify.addHook('preHandler', authMiddleware);

    // get list of courses with pagination and filters
    fastify.get('/', getCoursesList);

    // get details of course by course id
    fastify.get('/:courseId', getCourseDetails);
    
    // course routes starts here.
    fastify.post('/', createCourse);

    fastify.put("/:courseId/curriculum", updateCourseCurriculum);


}