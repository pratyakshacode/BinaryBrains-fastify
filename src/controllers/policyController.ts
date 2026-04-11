/**
 * Policy Controller
 * -----------------
 * Handles creation, fetching, updating, and soft deletion of RBAC policies.
 *
 * Features:
 *  - Create Policy based on Role + Permission + Resource + Scope
 *  - Soft delete Policy
 *  - Fetch single or multiple Policies (paginated)
 *  - Update Policy (PUT)
 *  - Bulk Grant/Revoke Access Control (ACL)
 *
 * Logging Conventions:
 *  - `info` → Describes the action being performed
 *  - `debug` → Shows detailed request or DB payload for debugging
 *
 * Error Handling:
 *  - Returns consistent status messages
 *  - Logs internal system errors without leaking internals to client
 */

import { FastifyRequest, FastifyReply } from 'fastify';
import { isInvalid } from '../utils/util';
import { HTTP_STATUS_CODE, HTTP_STATUS_MESSAGES } from '../utils/httpUtils';
import {
  createRecords,
  updateRecords,
  getSingleRecord,
  getFilteredRecordsWithPagination,
} from '../utils/sql/sqlUtils';
import { Policy } from '../entities/Policy';
import { Role } from '../entities/Role';
import { Permission } from '../entities/Permission';
import { Resource } from '../entities/Resource';
import { Scope } from '../entities/Scope';
import { logger } from '../utils/logger';


/**
 * Create Policy
 */
export const createPolicy = async (request: FastifyRequest, reply: FastifyReply) => {
  request.server.log.info("Running createPolicy...");

  try {
    request.server.log.debug(`Request Body: ${JSON.stringify(request.body)}`);

    const { role, permission, resource, scope } = request.body as any;
    // @ts-ignore
    const userId = request.user?.id;

    if (isInvalid(role) || isInvalid(permission) || isInvalid(resource) || isInvalid(scope)) {
      request.server.log.info("Required fields missing.");
      return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
        status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
        message: "role, permission, resource, and scope are required.",
      });
    }

    request.server.log.info("Validating referenced entities...");
    const [roleDoc, permDoc, resDoc, scopeDoc] = await Promise.all([
      getSingleRecord(Role, { where: { name: role.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Permission, { where: { name: permission.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Resource, { where: { name: resource.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Scope, { where: { name: scope.toLowerCase(), isDeleted: 0 }}),
    ]);

    if (!roleDoc || !permDoc || !resDoc || !scopeDoc) {
      request.server.log.info("Invalid referenced entity names provided.");
      return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
        status: HTTP_STATUS_MESSAGES.NOT_FOUND,
        message: "One or more referenced entities do not exist.",
      });
    }

    request.server.log.info("Checking for existing identical policy...");
    const existingPolicy = await getSingleRecord(Policy, {
      where: {
        role: roleDoc,
        permission: permDoc,
        resource: resDoc,
        scope: scopeDoc,
        isDeleted: 0,
      },
    });

    if (existingPolicy) {
      request.server.log.info("Duplicate Policy detected.");
      return reply.status(HTTP_STATUS_CODE.CONFLICT).send({
        status: HTTP_STATUS_MESSAGES.CONFLICT,
        message: "This policy already exists.",
      });
    }

    request.server.log.info("Creating new policy...");
    const newPolicy = await createRecords(Policy, {
      role: roleDoc,
      permission: permDoc,
      resource: resDoc,
      scope: scopeDoc,
      createdBy: { id: userId },
      updatedBy: { id: userId },
      isDeleted: 0,
    });

    request.server.log.debug(`Created Policy: ${JSON.stringify(newPolicy)}`);

    return reply.status(HTTP_STATUS_CODE.CREATED).send({
      status: HTTP_STATUS_MESSAGES.CREATED,
      message: "Policy created successfully.",
      data: newPolicy,
    });

  } catch (error: any) {
    request.server.log.info("Error in createPolicy");
    request.server.log.error(error);
    return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
      status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
      message: "Internal Server Error",
    });
  }
};


/**
 * Soft Delete Policy
 */
export const deletePolicy = async (
  request: FastifyRequest<{ Params: { policyId: string } }>,
  reply: FastifyReply
) => {
  request.server.log.info("Running deletePolicy...");

  try {
    request.server.log.debug(`Params: ${JSON.stringify(request.params)}`);
    const { policyId } = request.params;
    // @ts-ignore
    const userId = request.user?.id;

    if (isInvalid(policyId)) {
      request.server.log.info("Policy ID missing.");
      return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
        status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
        message: "Policy ID is required.",
      });
    }

    const result = await updateRecords(Policy, { id: policyId, isDeleted: 0 }, {
      isDeleted: 1,
      updatedBy: userId,
      updatedAt: new Date(),
    });

    if (isInvalid(result)) {
      request.server.log.info("Policy not found.");
      return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
        status: HTTP_STATUS_MESSAGES.NOT_FOUND,
        message: "Policy not found.",
      });
    }

    return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
      status: HTTP_STATUS_MESSAGES.SUCCESS,
      message: "Policy deleted successfully.",
      data: result,
    });

  } catch (error: any) {
    request.server.log.info("Error in deletePolicy");
    request.server.log.error(error);
    return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
      status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
      message: "Internal Server Error",
    });
  }
};


/**
 * Get paginated policies
 */
export const getPolicies = async (request: FastifyRequest, reply: FastifyReply) => {
  request.server.log.info("Running getPolicies...");

  try {
    request.server.log.debug(`Query: ${JSON.stringify(request.query)}`);

    const { page = '1', limit = '10' } = request.query as any;

    const result = await getFilteredRecordsWithPagination(
      Policy,
      { page: Number(page), limit: Number(limit),  },
      { isDeleted: 0 },
    );

    request.server.log.debug(`Policies Result: ${JSON.stringify(result)}`);

    return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
      status: HTTP_STATUS_MESSAGES.SUCCESS,
      message: "Policies fetched successfully.",
      data: result,
    });

  } catch (error: any) {
    request.server.log.info("Error in getPolicies");
    request.server.log.error(error);
    return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
      status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
      message: "Internal Server Error",
    });
  }
};


/**
 * Get Policy by ID
 */
export const getPolicyById = async (
  request: FastifyRequest<{ Params: { policyId: string } }>,
  reply: FastifyReply
) => {
  request.server.log.info("Running getPolicyById...");

  try {
    const { policyId } = request.params;
    request.server.log.debug(`PolicyId: ${policyId}`);

    if (isInvalid(policyId)) {
      return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
        status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
        message: "Policy ID is missing.",
      });
    }

    const policy = await getSingleRecord(Policy, {where: { id: policyId, isDeleted: 0 }});

    if (isInvalid(policy)) {
      return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
        status: HTTP_STATUS_MESSAGES.NOT_FOUND,
        message: "Policy not found.",
      });
    }

    return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
      status: HTTP_STATUS_MESSAGES.SUCCESS,
      message: "Policy fetched successfully.",
      data: policy,
    });

  } catch (error: any) {
    request.server.log.info("Error in getPolicyById");
    request.server.log.error(error);
    return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
      status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
      message: "Internal Server Error",
    });
  }
};


/**
 * Update Policy (PUT)
 */
export const updatePolicy = async (
  request: FastifyRequest<{ Params: { policyId: string }; Body: { role?: string; permission?: string; resource?: string; scope?: string } }>,
  reply: FastifyReply
) => {
  request.server.log.info("Running updatePolicy...");

  try {
    const { policyId } = request.params;
    const { role, permission, resource, scope } = request.body;
    // @ts-ignore
    const userId = request.user?.id;

    request.server.log.debug(`Updating Policy: ${policyId}`);

    if (isInvalid(policyId) || isInvalid(role) || isInvalid(permission) || isInvalid(resource) || isInvalid(scope)) {
      request.server.log.info("Missing required fields.");
      return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
        status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
        message: "role, permission, resource, and scope are required.",
      });
    }

    const [roleDoc, permDoc, resDoc, scopeDoc] = await Promise.all([
      getSingleRecord(Role, { where: { name: role.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Permission, { where: { name: permission.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Resource, { where: { name: resource.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Scope, { where: { name: scope.toLowerCase(), isDeleted: 0 }}),
    ]);

    if (!roleDoc || !permDoc || !resDoc || !scopeDoc) {
      request.server.log.info("Invalid reference(s).");
      return reply.status(HTTP_STATUS_CODE.NOT_FOUND).send({
        status: HTTP_STATUS_MESSAGES.NOT_FOUND,
        message: "Referenced entities not found.",
      });
    }

    const updatedPolicy = await updateRecords(
      Policy,
      { id: policyId, isDeleted: 0 },
      {
        role: roleDoc,
        permission: permDoc,
        resource: resDoc,
        scope: scopeDoc,
        updatedBy: { id: userId },
        updatedAt: new Date(),
      }
    );

    request.server.log.debug(`Policy updated: ${JSON.stringify(updatedPolicy)}`);

    return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
      status: HTTP_STATUS_MESSAGES.SUCCESS,
      message: "Policy updated successfully.",
      data: updatedPolicy,
    });

  } catch (error: any) {
    request.server.log.info("Error in updatePolicy");
    request.server.log.error(error);
    return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
      status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
      message: "Internal Server Error",
    });
  }
};



/**
 * Bulk ACL Update:
 * accessControls: [
 *   { role, permission, resource, scope, grantOrRevoke: "grant" | "revoke" }
 * ]
 */
export const updateAccessControlList = async (
  request: FastifyRequest<{ Body: { accessControls: AccessControl[] } }>,
  reply: FastifyReply
) => {
  request.server.log.info("Running updateAccessControlList...");

  try {
    const accessControls = request.body?.accessControls;
    // @ts-ignore
    const userId = request.user?.id;

    request.server.log.debug(`AccessControl Payload: ${JSON.stringify(accessControls)}`);

    if (!Array.isArray(accessControls) || accessControls.length === 0) {
      return reply.status(HTTP_STATUS_CODE.BAD_REQUEST).send({
        status: HTTP_STATUS_MESSAGES.BAD_REQUEST,
        message: "accessControls is required and must be a non-empty array.",
      });
    }

    for (const ac of accessControls) {
      if (ac.grantOrRevoke === "grant") {
        await createAccessControl(ac, userId, request);
      } else if (ac.grantOrRevoke === "revoke") {
        await deleteAccessControl(ac, userId, request);
      }
    }

    return reply.status(HTTP_STATUS_CODE.SUCCESS).send({
      status: HTTP_STATUS_MESSAGES.SUCCESS,
      message: "Access control updated successfully.",
    });

  } catch (error: any) {
    request.server.log.info("Error in updateAccessControlList");
    request.server.log.error(error);
    return reply.status(HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send({
      status: HTTP_STATUS_MESSAGES.INTERNAL_SERVER_ERROR,
      message: "Internal Server Error",
    });
  }
};


interface AccessControl {
  role: string;
  permission: string;
  resource: string;
  scope: string;
  grantOrRevoke?: "grant" | "revoke";
}


/**
 * Helper: Create/Restore Policy
 */
export async function createAccessControl(ac: AccessControl, userId: string, request: FastifyRequest) {
  request.server.log.info("Executing createAccessControl...");

  try {
    const { role, permission, resource, scope } = ac;

    if (isInvalid(role) || isInvalid(permission) || isInvalid(resource) || isInvalid(scope)) {
      request.server.log.info("Invalid AccessControl entry.");
      return;
    }

    const [roleDoc, permDoc, resDoc, scopeDoc] = await Promise.all([
      getSingleRecord(Role, { where: { name: role.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Permission, { where: { name: permission.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Resource, { where: { name: resource.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Scope, { where: { name: scope.toLowerCase(), isDeleted: 0 }}),
    ]);

    if (!roleDoc || !permDoc || !resDoc || !scopeDoc) {
      request.server.log.info("Invalid references in createAccessControl.");
      return;
    }

    // Check if policy already exists (undeleted)
    const existingPolicy = await getSingleRecord(Policy, {
      where: {
        role: roleDoc,
        permission: permDoc,
        resource: resDoc,
        scope: scopeDoc,
        isDeleted: 0,
      },
    });

    if (existingPolicy) {
      request.server.log.info("Policy already exists. Nothing to create.");
      return existingPolicy;
    }

    request.server.log.info("Creating or restoring policy...");

    const newPolicy = await createRecords(Policy, {
      role: roleDoc,
      permission: permDoc,
      resource: resDoc,
      scope: scopeDoc,
      createdBy: { id: userId },
      updatedBy: { id: userId },
      isDeleted: 0,
    });

    request.server.log.debug(`Policy Created/Restored: ${JSON.stringify(newPolicy)}`);

    return newPolicy;

  } catch (error: any) {
    logger.error("Error in createAccessControl", error);
    throw new Error("Failed to create policy.");
  }
}



/**
 * Helper: Soft Delete Policy
 */
export async function deleteAccessControl(ac: AccessControl, userId: string, request: FastifyRequest) {
  request.server.log.info("Executing deleteAccessControl...");

  try {
    const { role, permission, resource, scope } = ac;

    if (isInvalid(role) || isInvalid(permission) || isInvalid(resource) || isInvalid(scope)) {
      request.server.log.info("Invalid AccessControl entry.");
      return;
    }

    const [roleDoc, permDoc, resDoc, scopeDoc] = await Promise.all([
      getSingleRecord(Role, { where: { name: role.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Permission, { where: { name: permission.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Resource, { where: { name: resource.toLowerCase(), isDeleted: 0 }}),
      getSingleRecord(Scope, { where: { name: scope.toLowerCase(), isDeleted: 0 }}),
    ]);

    if (!roleDoc || !permDoc || !resDoc || !scopeDoc) {
      request.server.log.info("Invalid references in deleteAccessControl.");
      return;
    }

    const existingPolicy = await getSingleRecord(Policy, {
      where: {
        role: roleDoc,
        permission: permDoc,
        resource: resDoc,
        scope: scopeDoc,
        isDeleted: 0,
      },
    });

    if (!existingPolicy) {
      request.server.log.info("No matching active policy to delete.");
      return;
    }

    request.server.log.info("Soft deleting policy...");

    const result = await updateRecords(
      Policy,
      { id: (existingPolicy as any).id },
      { isDeleted: 1, updatedBy: { id: userId }, updatedAt: new Date() }
    );

    request.server.log.debug(`Policy deleted: ${JSON.stringify(result)}`);

    return result;

  } catch (error: any) {
    logger.error("Error in deleteAccessControl", error);
    throw new Error("Failed to delete policy.");
  }
}
