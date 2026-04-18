import { FastifyReply, FastifyRequest } from "fastify";
import { logger } from "../../utils/logger";
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from "../../utils/httpUtils";
import { getSingleRecord } from "../../utils/sql/sqlUtils";
import { FindOneOptions } from "typeorm";
import { Mcq } from "../../entities/MCQs";
import { isInvalid } from "../../utils/util";
import { SectionResourceMap } from "../../entities/SectionResourceMap";
import { Section } from "../../entities/Section";

export const getMcq = async (req: FastifyRequest, reply: FastifyReply) => {
    try {
        
        const { mcqId } = req.params as { mcqId: string };

        if (!mcqId) {
            logger.error("MCQ ID is required.");
            return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({ 
                status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
                message: "MCQ ID is required."
            });
        }

        logger.info(`Fetching MCQ with ID: ${mcqId}`);

        // Fetch mcq record
        const mcqQuery: FindOneOptions<Mcq> = {
            where: { id : mcqId }
        }

        const mcq: any = await getSingleRecord(Mcq, mcqQuery);
        const sectionResourceMapQuery: FindOneOptions<SectionResourceMap> = {
            where: {
                resourceId: mcq.id
            },
            select: {
                sectionId: true,
            }
        }

        const sectionResource: Partial<SectionResourceMap> = 
        await getSingleRecord(SectionResourceMap, sectionResourceMapQuery) as Partial<SectionResourceMap>;

        if(!isInvalid(sectionResource)) {
            mcq['sectionId'] = sectionResource.sectionId

            const sectionQuery: FindOneOptions<Section> = {
                where: { 
                    id: sectionResource.sectionId
                }
            }
            const section: Partial<Section> = await getSingleRecord(Section, sectionQuery) as Partial<Section>;
            mcq['sectionTitle'] = section.title
        }

        if(isInvalid(mcq)) {
            logger.error(`MCQ with ID ${mcqId} not found.`);
            return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({ 
                status: HTTP_STATUS_MESSAGES.NOT_FOUND,
                message: `MCQ with ID ${mcqId} not found.`
            });
        }

        return reply.status(HTTP_STATUS_CODE.SUCCESS).send({ 
            status: HTTP_STATUS_MESSAGES.SUCCESS,
            data: mcq
         });

    } catch (error) {
        logger.error("Error fetching MCQ:", error);
        return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({ 
            status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
            message: "An error occurred while fetching the MCQ."
        });
    }
}