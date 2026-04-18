import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { isInvalid } from "../../utils/util";
import { FindOneOptions } from "typeorm";
import { Mcq } from "../../entities/MCQs";
import { getSingleRecord, updateRecord } from "../../utils/sql/sqlUtils";
import { SectionResourceMap, ResourceType } from "../../entities/SectionResourceMap";
import { User } from "../../entities/User";

export const updateMcq = async (req: FastifyRequest, res: FastifyReply) => {
    try {
        const { mcqId } = req.params as { mcqId: string };
        const userId = (req.user as any)?.id; // Adjust based on your JWT setup
        
        if(isInvalid(mcqId)) {
            return res.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ 
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST, message: "MCQ ID is required."
            });
        }

        const { title, explanation, type, options, correctAnswer, sectionId } = req.body as {
            title?: string;
            explanation?: string;
            type?: "SINGLE_CHOICE" | "MULTI_SELECT" | "TRUE_FALSE";
            options?: string[];
            correctAnswer?: string[];
            sectionId?: string | null; // Passed from frontend
        };

        const updateData: any = {};
        if (!isInvalid(title)) updateData.title = title;
        if (!isInvalid(explanation)) updateData.explanation = explanation;
        if (!isInvalid(type)) updateData.type = type;
        if (!isInvalid(options)) updateData.options = options;
        if (!isInvalid(correctAnswer)) updateData.correctAnswer = correctAnswer;

        const mcqQuery: FindOneOptions<Mcq> = { where: { id: mcqId } };
        const mcq: Partial<Mcq> = await getSingleRecord(Mcq, mcqQuery) as Partial<Mcq>;

        if(isInvalid(mcq)) {
            return res.status(HTTP_STATUS_CODE.NOT_FOUND).send({ 
                status: HTTP_STATUS_MESSAGES.NOT_FOUND, message: `MCQ not found.`
            });
        }

        // 1. Update the actual MCQ
        if (Object.keys(updateData).length > 0) {
            await updateRecord(Mcq, { id: mcqId }, updateData);
        }

        // 2. Handle Section Mapping Logic
        if (sectionId !== undefined) {
            const existingMap = await SectionResourceMap.findOne({ where: { resourceId: mcqId } });

            if (sectionId === null) {
                // Remove from section entirely
                if (existingMap) await existingMap.remove();
            } else {
                // If it's moving to a NEW section or being added for the first time
                if (!existingMap || existingMap.sectionId !== sectionId) {
                    
                    // Find the highest orderIndex in the new target section
                    const highestMap = await SectionResourceMap.findOne({
                        where: { sectionId: sectionId },
                        order: { orderIndex: 'DESC' }
                    });
                    const nextOrder = highestMap ? highestMap.orderIndex + 1 : 0;

                    if (existingMap) {
                        // Move existing map
                        existingMap.sectionId = sectionId;
                        existingMap.orderIndex = nextOrder;
                        existingMap.updatedBy = { id: userId } as User;
                        await existingMap.save();
                    } else {
                        // Create brand new map
                        const newMap = new SectionResourceMap();
                        newMap.sectionId = sectionId;
                        newMap.resourceId = mcqId;
                        newMap.resourceType = ResourceType.MCQ;
                        newMap.resourceTitle = updateData.title || mcq!.title;
                        newMap.orderIndex = nextOrder;
                        newMap.createdBy = { id: userId } as User;
                        newMap.updatedBy = { id: userId } as User;
                        await newMap.save();
                    }
                }
            }
        }

        return res.status(HTTP_STATUS_CODE.SUCCESS).send({ 
            status: HTTP_STATUS_MESSAGES.SUCCESS, message: "MCQ updated successfully"
        });
        
    } catch (error) {
        logger.error("Error in updateMcq:", error);
        return res.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR, message: "Error updating MCQ."
        });
    }
}