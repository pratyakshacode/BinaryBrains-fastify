import "fastify";

// 🔥 Declare globally (NOT exported)
declare global {
  interface JwtUser {
    id: string;
    email: string;
    role: string;
    organizationId?: string | null;
  }
}

// 🔥 Augment Fastify types
declare module "fastify" {
  interface FastifyRequest {
    user: JwtUser;  // now works
  }
}