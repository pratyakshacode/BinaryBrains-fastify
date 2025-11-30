import { FastifyRequest, FastifyReply } from 'fastify'
import { isInvalid } from '../../utils/util';
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from '../../utils/httpUtils';
import { Course } from '../../models/course/courseModel';
import { MongoService } from '../../utils/dbUtil';
import { logger } from '../../utils/logger';

export const createCourse = async (req: FastifyRequest, reply: FastifyReply) => {

    try {

        logger.info("Request recieved for creating the new course.");
        const requiredFields = ['title', 'description', 'backgroundURL', 'type', 'amount', 'tags'];

        const body = req.body;

        if(isInvalid(body)) {

            logger.info("Empty body found in request. Returing bad request.")
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Required fields for creation of the course is missing."
            })
        }

        const recievedFields = Object.keys(body);
        const missingFields = []

        requiredFields.forEach((field) => {
            if(!recievedFields.includes(field)) {
                missingFields.push(field);
            }
        });

        if(missingFields.length > 0) {

            logger.info(`
                Following required fields are missing in body : ${missingFields.join(", ")}`
            )
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: `Following fields are required to create course : ${missingFields.join(", ")}`
            });
        }

        const instructors = body['instructors'];
        let validInstructorField = false;

        if(!isInvalid(instructors) && Array.isArray(instructors) && instructors.length > 0) {

            validInstructorField = true;
            logger.info("Instructors information found")

            for(let instructor of instructors) {
                if(isInvalid(instructor.name) || 
                    isInvalid(instructor.description) || 
                    isInvalid(instructor.experience)
                ) {
                    return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                        status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                        message: "Please provide the required details of instructor"
                    })
                };
            }
        }

        const createObj = {}

        requiredFields.forEach((field) => {
            createObj[field] = body[field];
        });

        if(validInstructorField) {
            createObj['instructors'] = instructors;
        }

        logger.debug(`
            All required field are found. Creating new course with the fields : 
            ${JSON.stringify(createObj)}
        `);

        const service = new MongoService(Course, {});
        const newCourse = await service.create(createObj, req.user);

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Course created successfully.",
            data: newCourse
        });

    } catch (error) {

        logger.error("Error in createCourse", error.message);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Error in creating new course. Please contact admin!"
        });
    }
}