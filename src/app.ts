/**
 * File contains the router and plugins registration code.
 */

import Fastify from 'fastify';
import fastifyCors from '@fastify/cors';
import fastifyMongodb from '@fastify/mongodb';
import fastifyJwt, { Secret } from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import dotenv from 'dotenv';
import helloWorldRouter from './routes/helloWorldRouter';
import authRouter from './routes/authRouter';
import mongoosePlugin from './plugins/mongoose';

dotenv.config();
const app = Fastify({ logger: true });

import { permissionRoutes } from './routes/permissionRouter';
import { policyRoutes } from './routes/policyRouter';
import { roleRoutes } from './routes/roleRouter';
import { resourceRoutes } from './routes/resourceRouter';
import { scopeRoutes } from './routes/scopeRouter';
import { courseAdminRouter } from './routes/course/courseAdminRouter';
import { organizationRouter } from './routes/organizationRouter';
import { articleRouter } from './routes/articleRouter';
import { sectionRouter } from './routes/sectionRouter';
import { mcqRouter } from './routes/mcqRouter';
import { resourceRouter } from './routes/resources/resourceRouter';
import { courseRouter } from './routes/course/courseRouter';

// registering cors to get the requests.
app.register(fastifyCors, {
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT']
});

// Register mongoose plugin
app.register(mongoosePlugin);

// mongodb connection
app.register(fastifyMongodb, {
    forceClose: true,
    url: process.env.MONGO_DB_URI
});

// to set the cookies
app.register(fastifyCookie);

// registering jwt
app.register(fastifyJwt, {
    secret: process.env.JWT_SECRET as Secret,
    cookie: {
        cookieName: 'jwtToken',
        signed: false
    }
});

// ALL ROUTES WILL COME HERE
app.register(helloWorldRouter, { prefix : '/api/helloWorld' });
app.register(authRouter, { prefix: '/api/auth' });

// RBAC ROUTES
app.register(permissionRoutes, { prefix: '/api/permission' });
app.register(policyRoutes, { prefix: '/api/policy' });
app.register(roleRoutes, { prefix: '/api/role' });
// app.register(resourceRoutes, { prefix: '/api/resource'});
app.register(scopeRoutes, { prefix: '/api/scope' });
app.register(courseAdminRouter, { prefix: '/api/admin/course'})
app.register(organizationRouter, { prefix: '/api/organization'})

// RESOURCES ROUTES
app.register(articleRouter, { prefix: '/api/article' });
app.register(mcqRouter, { prefix: '/api/mcq' });
app.register(sectionRouter, { prefix: '/api/section' });
app.register(resourceRouter, { prefix: '/api/resources' })

// PUBLIC COUŘSE ROUTES
app.register(courseRouter, { prefix: '/api/course' });

// --- HEALTH CHECK / ROOT ROUTE ---
app.get('/', async (request, reply) => {
    return {
        name: 'Binary Brains API',
        status: 'online',
        message: 'Welcome to the Binary Brains Backend! 🚀',
        environment: process.env.NODE_ENV || 'development',
        timestamp: new Date().toISOString()
    };
});

app.get('/health', async (request, reply) => {
    // This is useful for automated pinging services or Railway health checks
    return reply.status(200).send({ status: 'OK' });
});

export default app;