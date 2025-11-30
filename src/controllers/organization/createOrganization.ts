import { FastifyReply, FastifyRequest } from "fastify";
import { isInvalid } from "../../utils/util";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Organization } from "../../entities/Organization";
import { SQLService } from "../../utils/sql/SQLService";
import { logger } from "../../utils/logger";


export const createOrganization = async (req: FastifyRequest, reply: FastifyReply) => {
    try {

        const { title, description } = req.body as { title: string, description: string };
        if(isInvalid(title) || isInvalid(description)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Please provide all required fields to create organization."
            });
        }
        
        logger.info(`Creating new organization with title ${title}`);
        const service = new SQLService<typeof Organization>(Organization, { organizationScoped: false });

        const createObject = {
            title,
            description
        } as Partial<typeof Organization>

        const record = await service.create(createObject, req.user);
        // const record = {}
        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Organization created successfully!",
            data: record
        });

    } catch (error) {
        
        if (error?.code === "ER_DUP_ENTRY" || error?.errno === 1062) {
        return reply.status(HTTP_STATUS_CODE.CONFLICT).send({
                status: HTTP_STATUS_MESSAGES.CONFLICT,
                message: "An organization with this title already exists.",
            });
        }
        logger.info("Error in createOrganization", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Error in creating organization."
        })
    }
}