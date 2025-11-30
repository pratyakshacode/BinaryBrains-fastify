/**
 * RBAC Utility Module (TypeScript Version)
 * ----------------------------------------
 * Builds and retrieves an in-memory nested RBAC policy map.
 */

import { Policy } from "../entities/Policy";
import { config } from "../config/config";
import { getCacheData, setCacheData } from "./cache/cacheUtils";
import { getAllRecordsWithFilter } from "./sql/sqlUtils";
import { RBAC_POLICY_MAP_CACHE_KEY } from "./cache/cacheKeys";
import { logger } from "./logger";
export interface Role {
  name: string;
}

export interface Permission {
  name: string;
}

export interface Resource {
  name: string;
}

export interface Scope {
  name: string;
}

export interface PolicyType {
  id: string;
  role: Role;
  permission: Permission;
  resource: Resource;
  scope: Scope;
}

export type RBACMap = Record<
  string, // role
  Record<
    string, // resource
    Record<
      string, // permission
      Record<string, string> // scope → policy ID
    >
  >
>;


/**
 * Builds a nested RBAC policy map.
 */
export const buildRBACMap = async (policies: PolicyType[]): Promise<RBACMap> => {
  try {
    const policiesMap: RBACMap = {};

    for (const policy of policies) {
      const role = policy?.role?.name?.toUpperCase();
      const permission = policy?.permission?.name?.toUpperCase();
      const resource = policy?.resource?.name?.toUpperCase();
      const scope = policy?.scope?.name?.toUpperCase();

      if (!role || !permission || !resource || !scope) continue;

      // Initialize nested structure safely
      policiesMap[role] ??= {};
      policiesMap[role][resource] ??= {};
      policiesMap[role][resource][permission] ??= {};

      policiesMap[role][resource][permission][scope] = policy.id;
    }

    return policiesMap;
  } catch (err) {
    logger.error("Error in buildRBACMap:", err);
    return {};
  }
};

/**
 * Retrieves the RBAC policy map from Redis cache if available.
 * Otherwise, fetches policies from the database, builds the map, and caches it.
 */
export const getRBACPolicyMap = async (): Promise<RBACMap> => {
  try {
    logger.info("Fetching RBAC policy map from cache...");

    let policiesMap = (await getCacheData(RBAC_POLICY_MAP_CACHE_KEY)) as RBACMap | null;

    if (!policiesMap) {
      logger.info("RBAC cache miss → fetching from database...");

      const policyQuery: Record<string, unknown> = {};
      const policyRelations = { permission: true, resource: true, scope: true, role: true };

      // Ensure this returns PolicyType[]
      const policies = (await getAllRecordsWithFilter(
        Policy,
        { where: policyQuery, relations: policyRelations }
      )) as PolicyType[];

      policiesMap = await buildRBACMap(policies);

      await setCacheData(RBAC_POLICY_MAP_CACHE_KEY, policiesMap, config.RBAC_CACHE_TIME);
    } else {
      logger.info("RBAC cache hit.");
    }

    logger.debug("RBAC policy map successfully loaded.");
    return policiesMap;
  } catch (err) {
    logger.error("Error in getRBACPolicyMap:", err);
    return {};
  }
};
