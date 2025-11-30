/**
 * File contains the service class to perform the operations with sql
 */

import { Repository, FindOptionsWhere, FindManyOptions, Like, EntityTarget } from "typeorm";
import { AppDataSource } from "../../config/database";
import { isInvalid } from "../util";

interface BaseCrudOptions {
  organizationScoped?: boolean;
}

interface PaginationOptions<T> {
  page?: number;
  limit?: number;
  filter?: Partial<T>;
  search?: string;
  searchFields?: (keyof T)[];
  sortBy?: keyof T;
  sortOrder?: "asc" | "desc";
  relations?: string[];
}

interface PaginatedResponse<T> {
  data: T[];
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export class SQLService<T> {

    private repo: Repository<T>;
    private organizationScoped: boolean;

    constructor(entity: EntityTarget<T>, options: BaseCrudOptions = {}) {
        this.repo = AppDataSource.getRepository(entity);
        this.organizationScoped = options.organizationScoped ?? true;
    }

    // -------------------------------------------
    //  BUILD CONDITIONS
    // -------------------------------------------
    private buildConditions(
        user: any,
        extra: FindOptionsWhere<T> = {}
    ): FindOptionsWhere<T> {
        const conditions: any = {
        isDeleted: false,
        ...extra,
        };

        if (this.organizationScoped) {

            if(isInvalid(user) || isInvalid(user.organizationId)) 
                throw Error("Organization id is needed for organization scope");

            conditions.organizationId = user.organizationId;
        }

        return conditions;
    }

    // -------------------------------------------
    //  CREATE
    // -------------------------------------------
    async create(data: Partial<T>, user: any): Promise<T> {
        const createObject: any = {
        ...data,
        createdBy: user.id,
        updatedBy: user.id,
        }
        const entity: any = this.repo.create(createObject);

        if (this.organizationScoped) {
        entity.organizationId = user.organizationId;
        }

        return await this.repo.save(entity);
    }

    // -------------------------------------------
    //  GET BY ID
    // -------------------------------------------
    async getById(id: string, user: any, relations?: string[]): Promise<T | null> {
        return await this.repo.findOne({
        where: this.buildConditions(user, { id } as any),
        relations,
        });
    }

    // -------------------------------------------
    //  GET WITH FILTER
    // -------------------------------------------
    async getWithFilter(
        user: any,
        filter: FindOptionsWhere<T>,
        relations?: string[]
    ): Promise<T[]> {
        return await this.repo.find({
        where: this.buildConditions(user, filter),
        relations,
        });
    }

    // -------------------------------------------
    //  PAGINATED LIST
    // -------------------------------------------
    async paginatedList(
        user: any,
        options: PaginationOptions<T>,
    ): Promise<PaginatedResponse<T>> {
        const page = options.page ?? 1;
        const limit = options.limit ?? 10;
        const skip = (page - 1) * limit;

        let where: any = { ...(options.filter ?? {}) };

        if (options.search && options.searchFields?.length) {
        where = {
            ...where,
            $or: options.searchFields.map((field) => ({
            [field]: Like(`%${options.search}%`)
            })),
        };
        }

        const conditions = this.buildConditions(user, where);

        const orderField = (options.sortBy ?? "createdAt") as string;
        const orderDirection = options.sortOrder === "asc" ? "ASC" : "DESC";

        const [data, total] = await this.repo.findAndCount({
        where: conditions,
        skip,
        take: limit,
        order: { [orderField]: orderDirection } as any,
        relations: options.relations,
        });

        return {
        data,
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        };
    }

    // -------------------------------------------
    //  LIST ALL
    // -------------------------------------------
    async list(user: any, relations?: string[]): Promise<T[]> {
        return await this.repo.find({
        where: this.buildConditions(user),
        order: { createdAt: "DESC" } as any,
        relations,
        });
    }

    // -------------------------------------------
    //  UPDATE
    // -------------------------------------------
    async update(id: string, data: Partial<T>, user: any): Promise<T | null> {
        await this.repo.update(
        this.buildConditions(user, { id } as any),
        {
            ...data,
            updatedBy: user.id,
        } as any
        );

        return await this.getById(id, user);
    }

    async upsert(
        filter: FindOptionsWhere<T>,
        data: Partial<T>,
        user: any,
        relations?: string[]
        ): Promise<any> {
        const conditions = this.buildConditions(user, filter);

        // Step 1: Check if item exists (respecting organization scope)
        let existing = await this.repo.findOne({ where: conditions, relations });

        if (existing) {
            // UPDATE CASE
            await this.repo.update(conditions, {
            ...data,
            updatedBy: user.id,
            } as any);

            return await this.repo.findOne({
            where: conditions,
            relations,
            }) as T;
        }

        // INSERT CASE
        const createObject: any = {
            ...data,
            ...filter,
            createdBy: user.id,
            updatedBy: user.id,
        };

        if (this.organizationScoped) {
            createObject.organizationId = user.organizationId;
        }

        const entity = this.repo.create(createObject);

        return await this.repo.save(entity);
    }

    // -------------------------------------------
    //  SOFT DELETE
    // -------------------------------------------
    async softDelete(id: string, user: any): Promise<T | null> {
        await this.repo.update(
        this.buildConditions(user, { id } as any),
        {
            isDeleted: true,
            deletedBy: user.id,
            deletedAt: new Date(),
        } as any
        );

        return await this.getById(id, user);
    }

    
}