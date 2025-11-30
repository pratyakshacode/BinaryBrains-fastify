import { FastifyReply, FastifyRequest } from "fastify";
import { SQLService } from "../../utils/sql/SQLService";
import { Organization } from "../../entities/Organization";
import { User } from "../../entities/User";
import { isInvalid } from "../../utils/util";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import UserOrganizationMap from "../../entities/UserOrganizationMap";
import { logger } from "../../utils/logger";

const organizationService = new SQLService(Organization, { organizationScoped: false });
const userService = new SQLService(User, { organizationScoped: false });
const userOrganizationMapService = new SQLService(UserOrganizationMap, { organizationScoped: false });

export const assignOwnerToOrganization = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        
        const { ownerId, organizationId } = req.body as { ownerId: string, organizationId: string};
        const currentUserId = (req.user as JwtUser).id;

        if(isInvalid(ownerId)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Invalid owner id found."
            })
        }

        if(isInvalid(organizationId)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "Invalid organization id found."
            })
        }

        logger.info(`Assigning ${ownerId} as owner of ${organizationId} on the request of ${currentUserId}`);

        const owner = await userService.getById(ownerId, req.user);

        if(isInvalid(owner)) {

            logger.info("Owner with given id not found. Returning not found reply.")
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Owner with given id not found."
            });
        }

        const organization = await organizationService.getById(organizationId, req.user);
        if(isInvalid(organization)) {
            logger.info("Organization with the given id not found. Returning not found reply.");
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Organization with the given id not found."
            })
        }

        logger.info("Setting the owner of the organization.")
        await organizationService.update(organizationId, { 
            owner: { id: ownerId } as User 
        }, req.user);

        logger.info("Making the owner as admin of organization.");
        await userService.update(ownerId, {
            role: 'admin'
        } as User, req.user);

        logger.info("Checking whether the user is a part of the organization.");

        const filter = { 
            organization: { id: organizationId },
            user: { id: ownerId }
        }

        const ownerIsAPartOfOrgs = await userOrganizationMapService.getWithFilter(req.user, filter);

        if(isInvalid(ownerIsAPartOfOrgs)) {

            logger.info("User is not a part of organization. Adding ..");
            const data: Partial<UserOrganizationMap> = {
                organization: { id: organizationId } as Organization,
                user: { id: ownerId } as User
            }
            const result = await userOrganizationMapService.create(data, req.user);
            logger.debug("Result for creation of user organization map: ", result);
        }

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: "Owner assigned to organization successfully!"
        });

        
    } catch (error) {
        console.log(error);
        logger.error("Error in assigningOwnerToOrganization", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "Error in assigning owner to organization."
        })
    }
}