import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { Mcq } from "../../entities/MCQs";

interface SingleSubmission {
    userAnswers: string[]; // Always an array (handles single, multi, and T/F)
}

export const evaluateSingleMcq = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        const { mcqId } = req.params as { mcqId: string };
        const { userAnswers } = req.body as SingleSubmission;

        if (!mcqId) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "MCQ ID is required."
            });
        }

        if (!Array.isArray(userAnswers)) {
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "userAnswers must be an array of strings."
            });
        }

        // 1. Fetch the master question (which contains the hidden correct answers)
        const question = await Mcq.findOne({
            where: { id: mcqId, isDeleted: false },
            select: ["id", "type", "correctAnswer", "explanation"] 
        });

        if (!question) {
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: "Question not found."
            });
        }

        // 2. Evaluation Engine
        let isCorrect = false;
        const realAns = question.correctAnswer || [];

        if (userAnswers.length > 0) {
            // Sort both arrays so the order the student clicked them doesn't cause a false negative
            const sortedUserAns = [...userAnswers].sort();
            const sortedRealAns = [...realAns].sort();

            if (JSON.stringify(sortedUserAns) === JSON.stringify(sortedRealAns)) {
                isCorrect = true;
            }
        }

        // 3. Return the exact data the UI needs to show the result
        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            data: {
                isCorrect,
                correctAnswers: realAns,
                explanation: question.explanation || "No explanation provided for this question."
            }
        });

    } catch (error) {
        logger.error("Error in evaluateSingleMcq:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An error occurred while checking the answer."
        });
    }
}