/*
    File contains utility functions for performing DB operations (TypeORM + NodeCache)
*/

import { BaseEntity, FindManyOptions } from "typeorm";
import { getCacheData, setCacheData } from '../cache/cacheUtils'; // your NodeCache utils
import { config } from "../../config/config"; 
import { getLogger } from "../logger";

const logger = getLogger();

export async function getAllRecords(
  model: typeof BaseEntity,
  key: string = "",
  isCache: boolean = false,
  cacheLimit: number = config.DEFAULT_CACHE_TIME
) {
  try {
    const hasIsDeletedField = model.getRepository().metadata.columns.some(
      (column) => column.propertyName === "isDeleted"
    );

    const query: FindManyOptions = hasIsDeletedField ? { where: { isDeleted: false } } : {};

    if (isCache) {
      const cacheData = getCacheData(key);
      if (cacheData) {
        logger.info(`Cache hit [${key}] → getAllRecords`);
        return cacheData;
      }

      const data = await model.find(query);
      logger.info(`Cache miss [${key}] → fetched from DB`);
      setCacheData(key, data, cacheLimit);
      return data;
    }

    return await model.find(query);
  } catch (err) {
    logger.error("ERROR in getAllRecords", err);
    throw err;
  }
}

// Creates a record in the DB
export async function createOneRecord(
  model: typeof BaseEntity,
  data: any
){
  try {
    const record = model.create(data);
    await record.save();
    return record;
  } catch (err) {
    logger.error("ERROR in createRecords", err);
    throw err;
  }
}

// Gets a single record by query
export async function getSingleRecord(
  model: typeof BaseEntity,
  query: any,
  key: string = "",
  isCache: boolean = false,
  cacheLimit: number = config.DEFAULT_CACHE_TIME
) {
  try {
    if (isCache) {
      const cacheData = getCacheData(key);
      if (cacheData) {
        logger.info(`Cache hit [${key}] → getSingleRecord`);
        return cacheData;
      }

      const data = await model.findOne(query);
      if (data) {
        logger.info(`Cache miss [${key}] → fetched from DB`);
        setCacheData(key, data, cacheLimit);
      }
      return data;
    }

    return await model.findOne(query);
  } catch (err) {
    logger.error("ERROR in getSingleRecord", err);
    throw err;
  }
}

// Gets all records matching a filter
export async function getAllRecordsWithFilter(
  model: typeof BaseEntity,
  query: any,
  key: string = "",
  isCache: boolean = false,
  cacheLimit: number = config.DEFAULT_CACHE_TIME
) {
  try {
    if (isCache) {
      const cacheData = getCacheData(key);
      if (cacheData) {
        logger.info(`Cache hit [${key}] → getAllRecordsWithFilter`);
        return cacheData;
      }

      const data = await model.find(query);
      logger.info(`Cache miss [${key}] → fetched from DB`);
      setCacheData(key, data, cacheLimit);
      return data;
    }

    return await model.find(query);
  } catch (err) {
    logger.error("ERROR in getAllRecordsWithFilter", err);
    throw err;
  }
}

// Deletes records matching the query
export async function deleteRecords(
  model: typeof BaseEntity,
  query: any
) {
  try {
    const data = await model.getRepository().createQueryBuilder().delete().where(query).execute();
    return data;
  } catch (err) {
    logger.error("ERROR in deleteRecords", err);
    throw err;
  }
}

// Updates or upserts records
export async function updateRecord(
  model: typeof BaseEntity,
  query: any,
  update: any,
  upsert: boolean = false
){
  try {
    if (upsert) {
      const newData = await model.upsert(query, update)
      return newData;
    }
    const newData = await model.update(query, update);
    return newData;
  } catch (err) {
    logger.error("ERROR in updateRecord", err);
    throw err;
  }
}

export async function getFilteredRecordsWithPagination<T>(
  model: typeof BaseEntity,
  page: { page: number; limit: number },
  query: any,
  orderBy?: any,
  select?: any,
  relations?: any,
  key: string = "",
  isCache: boolean = false,
  cacheLimit: number = config.DEFAULT_CACHE_TIME
) {
  try {
    if (isCache) {
      const cacheData = getCacheData(key);
      if (cacheData) {
        logger.info(`Cache hit [${key}] → getFilteredRecordsWithPagination`);
        return cacheData;
      }
    }

    const skip = (page.page - 1) * page.limit;
    const data = await model.find({
      select,
      where: query,
      relations,
      order: orderBy,
      skip,
      take: page.limit,
    });

    const totalCount = await model.count({ where: query });

    const result = {
      totalCount,
      page: page.page,
      limit: page.limit,
      data,
    };

    if (isCache) {
      setCacheData(key, result, cacheLimit);
    }

    return result;
  } catch (err) {
    logger.error("ERROR in getFilteredRecordsWithPagination", err);
    throw err;
  }
}

// Count records
export async function getRecordCount(
  model: typeof BaseEntity,
  query: any
) {
  try {
    const repository = model.getRepository();
    const count = await repository.count(query as any);
    return count;
  } catch (err) {
    logger.error("ERROR in getRecordCount", err);
    throw err;
  }
}