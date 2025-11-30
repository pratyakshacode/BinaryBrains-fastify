// File contains the auth middleware for the authentication

import { FastifyReply, FastifyRequest } from "fastify";

export const authMiddleware = async (req: FastifyRequest, reply: FastifyReply) => {
  try {
    const user = await req.jwtVerify<JwtUser>();
    req.user = user;
  } catch (err) {
    return reply.status(401).send({
      message: "Unauthorized",
      error: (err as Error).message,
    });
  }
};