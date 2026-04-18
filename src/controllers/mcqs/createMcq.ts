import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { isInvalid } from "../../utils/util";
import { Mcq, MCQType } from "../../entities/MCQs"; 
import { SectionResourceMap, ResourceType } from "../../entities/SectionResourceMap"; 
import { User } from "../../entities/User";

interface McqPayload {
    title: string;
    explanation?: string; 
    type: MCQType;
    options: string[];
    correctAnswer: string[]; // Standardized as an array for all question types
    isPublic?: boolean;
    sectionId?: string | null;
}

export const createMcqBatch = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        const { mcqs } = req.body as { mcqs: McqPayload[] };
        const user = req.user;

        // 1. Initial Payload Validation
        if (!mcqs || !Array.isArray(mcqs) || mcqs.length === 0) {
            logger.error("Missing or empty 'mcqs' array in request body.");
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ 
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "You must provide an array of MCQs to batch create."
            });
        }

        logger.info(`Starting batch creation for ${mcqs.length} MCQs.`);

        // 2. Strict Validation Loop (Validate all before saving any)
        for (const [index, mcq] of mcqs.entries()) {
            if (isInvalid(mcq.title) || isInvalid(mcq.type)) {
                return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ 
                    status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                    message: `Validation failed at question #${index + 1}: Missing title or type.`
                });
            }

            if (!Array.isArray(mcq.options) || mcq.options.length < 2) {
                return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ 
                    status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                    message: `Validation failed at question #${index + 1}: Must provide at least 2 options.`
                });
            }

            if (!Array.isArray(mcq.correctAnswer) || mcq.correctAnswer.length === 0) {
                return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ 
                    status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                    message: `Validation failed at question #${index + 1}: Must provide at least one correct answer.`
                });
            }

            if (mcq.type === "SINGLE_CHOICE" && mcq.correctAnswer.length > 1) {
                return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ 
                    status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                    message: `Validation failed at question #${index + 1}: SINGLE_CHOICE cannot have multiple correct answers.`
                });
            }
        }

        // 3. Save the MCQs to the Database
        const mcqEntities = mcqs.map(q => {
            const newMcq = new Mcq();
            newMcq.title = q.title;
            newMcq.explanation = q.explanation || "";
            newMcq.type = q.type as MCQType;
            newMcq.options = q.options;
            newMcq.correctAnswer = q.correctAnswer;
            newMcq.isPublic = q.isPublic ?? true; // Uncomment if your entity uses this
            newMcq.createdBy = { id : (req.user as JwtUser).id } as User
            return newMcq;
        });

        // TypeORM bulk-inserts these and returns the array with their new UUIDs attached
        const savedMcqs = await Mcq.save(mcqEntities);

        // 4. Handle Section Mappings (If any)
        const mappingsToCreate: SectionResourceMap[] = [];

        // --- NEW: Calculate the starting orderIndex for the target sections ---
        // 1. Get a unique list of all sectionIds in this batch
        const uniqueSectionIds = [...new Set(mcqs.map(q => q.sectionId).filter(Boolean))] as string[];
        
        // 2. Map each sectionId to its next available orderIndex
        const sectionNextOrder = new Map<string, number>();

        for (const secId of uniqueSectionIds) {
            // Find the item with the highest orderIndex currently in this section
            const highestMap = await SectionResourceMap.findOne({
                where: { sectionId: secId },
                order: { orderIndex: 'DESC' }
            });
            
            // If the section has items, start from the next number. Otherwise, start at 0.
            sectionNextOrder.set(secId, highestMap ? highestMap.orderIndex + 1 : 0);
        }

        // --- NEW: Grab the user ID safely for relations ---
        const userId = (req.user as JwtUser).id;

        // --- CREATE MAPPINGS ---
        for (let i = 0; i < mcqs.length; i++) {
            const originalPayload = mcqs[i];
            const newlySavedMcq = savedMcqs[i];

            if (originalPayload.sectionId) {
                const map = new SectionResourceMap();
                map.sectionId = originalPayload.sectionId;
                map.resourceId = newlySavedMcq.id;
                map.resourceType = ResourceType.MCQ;
                
                // FIXED: Populate the new missing columns
                map.resourceTitle = originalPayload.title;
                map.createdBy = { id: userId } as User;
                map.updatedBy = { id: userId } as User;
                
                // FIXED: Assign the correct dynamic orderIndex
                const nextOrder = sectionNextOrder.get(originalPayload.sectionId)!;
                map.orderIndex = nextOrder;
                
                // Increment the counter so the next question in the batch gets the next slot
                sectionNextOrder.set(originalPayload.sectionId, nextOrder + 1);
                mappingsToCreate.push(map);
            }
        }

        // Bulk insert the mappings
        if (mappingsToCreate.length > 0) {
            logger.info(`Creating ${mappingsToCreate.length} section mappings...`);
            await SectionResourceMap.save(mappingsToCreate);
        }

        logger.info("Batch MCQ creation successful.");

        return reply.status(HTTP_STATUS_CODE.CREATED).send({ 
            status: HTTP_STATUS_MESSAGES.CREATED,
            message: `Successfully created ${savedMcqs.length} questions.`,
            data: savedMcqs
        });

    } catch (error) {
        logger.error("Error in createMcqBatch", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An error occurred while processing the MCQ batch."
        });
    }
}