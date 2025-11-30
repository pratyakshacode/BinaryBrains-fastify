// Service class for performing the operations on mongodb

import { Model, Document, FilterQuery, UpdateQuery, PopulateOptions } from "mongoose";

interface BaseCrudOptions {
    organizationScoped?: boolean;
}

interface PaginationOptions<T> {
    page?: number;
    limit?: number;
    filter?: Partial<T>;
    search?: string;
    searchFields?: string[];
    sortBy?: string;
    sortOrder?: "asc" | "desc";
    populate?: PopulateOptions | PopulateOptions[];
}

interface PaginatedResponse<T> {
    data: T[];
    page: number;
    limit: number;
    total: number;
    totalPages: number;
}

export class MongoService<T> {

    private model: Model<T>;
    private organizationScoped: boolean;

    constructor(model: Model<T>, options: BaseCrudOptions = {}) {
        this.model = model;
        this.organizationScoped = options.organizationScoped ?? true;
    }

    private buildConditions(user: any, extra: FilterQuery<T> = {}): FilterQuery<T> {
        const conditions: FilterQuery<T> = {
          isDeleted: { $ne: true },
          ...extra,
        };

        if (this.organizationScoped) {
          (conditions as any).organizationId = user.organizationId;
        }

        return conditions;
    }

    // --------------------------
    // CREATE
    // --------------------------
    async create(data: Partial<T>, user: any): Promise<T> {
        const doc = new this.model({
          ...data,
          createdBy: user._id,
          updatedBy: user._id,
        } as any);

        if (this.organizationScoped) {
          (doc as any).organizationId = user.organizationId;
        }

        return await doc.save() as any;
    }

    // --------------------------
    // GET BY ID
    // --------------------------
    async getById(id: string, user: any, populate?: PopulateOptions | PopulateOptions[]): Promise<T | null> {
        let query = this.model.findOne(this.buildConditions(user, { _id: id }));

        if (populate) query = query.populate(populate);

        return await query;
    }

    // --------------------------
    // GET WITH FILTER
    // --------------------------
    async getWithFilter(
        user: any,
        filter: FilterQuery<T>,
        populate?: PopulateOptions | PopulateOptions[]
    ): Promise<T[]> {

        let query = this.model.find(this.buildConditions(user, filter));

        if (populate) query = query.populate(populate);

        return await query;
    }

    // --------------------------
    // PAGINATED LIST
    // --------------------------
    async paginatedList(
        user: any,
        options: PaginationOptions<T>
    ): Promise<PaginatedResponse<T>> {
        const page = options.page ?? 1;
        const limit = options.limit ?? 10;
        const skip = (page - 1) * limit;

        const filters: FilterQuery<T> = { ...options.filter as any };

        if (options.search && options.searchFields?.length) {
          (filters as any)["$or"] = options.searchFields.map((field) => ({
            [field]: { $regex: options.search, $options: "i" },
          }));
        }

        const conditions = this.buildConditions(user, filters);

        const sortField = options.sortBy ?? "createdAt";
        const sortOrder = options.sortOrder === "asc" ? 1 : -1;

        let query = this.model
          .find(conditions)
          .skip(skip)
          .limit(limit)
          .sort({ [sortField]: sortOrder });

        if (options.populate) query = query.populate(options.populate);

        const [data, total] = await Promise.all([
          query,
          this.model.countDocuments(conditions),
        ]);

        return {
          data,
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        };
    }

    // --------------------------
    // LIST ALL
    // --------------------------
    async list(user: any, populate?: PopulateOptions | PopulateOptions[]): Promise<T[]> {
        let query = this.model.find(this.buildConditions(user)).sort({ createdAt: -1 });

        if (populate) query = query.populate(populate);

        return await query;
    }

    // --------------------------
    // UPDATE
    // --------------------------
    async update(id: string, data: Partial<T>, user: any): Promise<T | null> {
        return await this.model.findOneAndUpdate(
          this.buildConditions(user, { _id: id }),
          {
            ...data,
            updatedBy: user._id,
          } as any,
          {
            new: true,
            lean: false,
          }
        );
    }

    // --------------------------
    // SOFT DELETE
    // --------------------------
    async softDelete(id: string, user: any): Promise<T | null> {
        return await this.model.findOneAndUpdate(
          this.buildConditions(user, { _id: id }),
          {
              isDeleted: true,
              deletedBy: user._id,
              deletedAt: new Date(),
          } as any,
          {
              new: true,
          }
        );
    }
}