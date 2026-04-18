import { FastifyReply, FastifyRequest } from "fastify";
import { isInvalid } from "../../utils/util";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { FindOneOptions } from "typeorm/find-options/FindOneOptions";
import { getSingleRecord, updateRecord } from "../../utils/sql/sqlUtils";
import { Mcq } from "../../entities/MCQs";

export const deleteMcq = async (req: FastifyRequest, res: FastifyReply) => {
    try {
        const { mcqId } = req.params as { mcqId: string };
        
        if(isInvalid(mcqId)) {
            logger.error("MCQ ID is required for deletion.");
            return res.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ 
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "MCQ ID is required for deletion."
             });
        }

        logger.info("Deleting MCQ with ID:", mcqId);

        const mcqQuery: FindOneOptions<Mcq> = {
             where: { id : mcqId }
        }
        
        const mcq = await getSingleRecord(Mcq, mcqQuery);

        if(isInvalid(mcq)) {
            logger.error(`MCQ with ID ${mcqId} not found for deletion.`);
            return res.status(HTTP_STATUS_CODE.NOT_FOUND).send({ 
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: `MCQ with ID ${mcqId} not found for deletion.`
             });
        }

        await updateRecord(Mcq, { id: mcqId}, { isDeleted: true });
        
        return res.status(HTTP_STATUS_CODE.SUCCESS).send({ 
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            message: `MCQ with ID ${mcqId} has been deleted successfully.`
         });
        
    } catch (error) {
        logger.error("Error in deleteMcq:", error);
        return res.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An error occurred while deleting the MCQ."
         });
    }
}   