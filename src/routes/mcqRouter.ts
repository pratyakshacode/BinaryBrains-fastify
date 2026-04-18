import { FastifyInstance } from "fastify";
import { getMcq } from "../controllers/mcqs/getMcq";
import { getListOfMcq } from "../controllers/mcqs/getListofMcq";
import { createMcqBatch } from "../controllers/mcqs/createMcq";
import { authMiddleware } from "../middlewares/auth/authMiddleware";
import { updateMcq } from "../controllers/mcqs/updateMcq";
import { deleteMcq } from "../controllers/mcqs/deleteMcq";
import { evaluateSingleMcq } from "../controllers/mcqs/evaluateSingleMcq";

export const mcqRouter = async (fastify: FastifyInstance) => {

    // All routes in this router will require authentication
    fastify.addHook("preHandler", authMiddleware);

    // GET /mcqs - Get list of MCQs with pagination and optional title filter
    fastify.get('/', getListOfMcq);

    // Evaluate the answer of mcq
    fastify.post('/:mcqId/evaluate', evaluateSingleMcq);

    // GET /mcqs/:mcqId - Get details of a single MCQ by ID
    fastify.get('/:mcqId', getMcq);

    // POST /mcqs - Create a new MCQ
    fastify.post('/', createMcqBatch);

    // PUT /mcqs/:mcqId - Update an existing MCQ by ID
    fastify.put('/:mcqId', updateMcq);

    // DELETE /mcqs/:mcqId - Soft delete an MCQ by ID (not implemented yet)
    fastify.delete("/:mcqId", deleteMcq);

}