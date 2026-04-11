// File contains the auth middleware for the authentication

import { FastifyReply, FastifyRequest } from "fastify";
import { HTTP_STATUS_CODE } from "../../utils/httpUtils";
import { logger } from "../../utils/logger";

export const authMiddleware = async (req: FastifyRequest, reply: FastifyReply) => {
  try {
    const user = await req.jwtVerify<JwtUser>();
    req.user = user;
  } catch (err) {
    logger.error("Error in authMiddleware: ", err);
    return reply.status(401).send({
      status: HTTP_STATUS_CODE.UNAUTHORIZED,
      message: "Unauthorized. Please login to access this resource."
    });
  }
};