/*
    File contains Node-Cache utility functions (Simplified TypeScript version)
*/

import NodeCache from "node-cache";
import { logger } from "../logger";

const localCache = new NodeCache({ stdTTL: 3600 });

/** Get cached data by key */
export async function getCacheData(key: string) {
  try {
    logger.info(`GETTING CACHE DATA FOR KEY: ${key}`);

    const cachedData = localCache.get(key);
    if (cachedData !== undefined) {
      logger.info("Cached Data FOUND (NodeCache)");
      return cachedData;
    } else {
      logger.info("Cached Data NOT FOUND (NodeCache)");
      return false;
    }
  } catch (err: any) {
    logger.error("ERROR ON GETTING CACHE DATA", err);
    throw err;
  }
}

/** Set data in cache with expiry (seconds) */
export async function setCacheData(key: string, data: any, cacheLimit?: number) {
  try {
    logger.info(`SETTING CACHE DATA FOR KEY: ${key}`);
    localCache.set(key, data, cacheLimit);
  } catch (err: any) {
    logger.error("ERROR ON CACHING DATA", err);
    throw err;
  }
}

/** Delete a specific key from cache */
export async function deleteCacheData(key: string) {
  try {
    logger.info(`DELETING CACHE DATA FOR KEY = ${key}`);
    localCache.del(key);
  } catch (err: any) {
    logger.error("ERROR ON DELETING CACHE KEY", err);
    throw err;
  }
}

/** Check if key exists */
export async function checkCacheDataExist(key: string) {
  try {
    logger.info(`CHECKING IF CACHE KEY EXISTS = ${key}`);
    return localCache.has(key);
  } catch (err: any) {
    logger.error("ERROR ON CHECKING CACHE KEY EXISTENCE", err);
    throw err;
  }
}

/** Get expiry time (in seconds) */
export async function getExpiryTimeInSec(key: string) {
  try {
    logger.info(`GETTING EXPIRY TIME FOR KEY = ${key}`);

    const ttl = localCache.getTtl(key);
    if (!ttl) return -1;
    return Math.floor((ttl - Date.now()) / 1000);
  } catch (err: any) {
    logger.error("ERROR ON GETTING TTL", err);
    throw err;
  }
}

/** Delete all keys with prefix */
export async function deleteCacheKeys(prefix: string) {
  try {
    logger.info(`DELETING CACHE DATA FOR KEYS WITH PREFIX = ${prefix}`);

    const keys = localCache.keys().filter((k) => k.startsWith(prefix));
    keys.forEach((k) => localCache.del(k));
    logger.info(`DELETED ${keys.length} KEYS HAVING PREFIX ${prefix} (NodeCache)`);
  } catch (err: any) {
    logger.error("ERROR ON DELETING KEYS BY PREFIX", err);
    throw err;
  }
}