import { FastifyReply, FastifyRequest } from "fastify";
import { isInvalid } from "../../utils/util";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { SQLService } from "../../utils/sql/SQLService";
import { Organization } from "../../entities/Organization";
import { logger } from "../../utils/logger";


export const getOrganizationById = async (req: FastifyRequest, reply: FastifyReply) => {
    try {

        const { organizationId } = req.params as { organizationId: string };

        if(isInvalid(organizationId)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Invalid organization id found."
            });
        }

        logger.info(`Getting the organization with id: ${organizationId}`);

        const service = new SQLService(Organization, { organizationScoped: false });
        
        const organization = await service.getById(organizationId, req.user);

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Organization fetched successfully!",
            data: organization
        })

    } catch (error) {
        
        logger.error("Error in getOrganization", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Error in getting organization."
        })
    }
}