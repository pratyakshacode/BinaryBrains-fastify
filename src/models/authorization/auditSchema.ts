import mongoose from "mongoose";

/**
 * Audit Schemas
 * --------------------------------------------
 * These schemas contain reusable audit fields
 * that can be applied to any MongoDB/Mongoose
 * schema using the spread operator.
 *
 * There are 2 variants:
 *
 * 1. auditSchemaWithOrganization
 *    - Used for organization-scoped (multi-tenant)
 *      resources such as batches, students, mentors,
 *      contests, institute-specific content, etc.
 *
 * 2. auditSchemaWithoutOrganization
 *    - Used for global/public resources that are not
 *      specific to any organization, such as public
 *      courses, global settings, platform-wide config,
 *      or shared feature flags.
 *
 * Both schemas include:
 *  - createdBy:   User who created the record
 *  - updatedBy:   User who last updated the record
 *  - deletedBy:   User who soft-deleted the record
 *  - deletedAt:   Timestamp to support soft delete flows
 */

// --------------------------------------------
// 1. Audit schema for organization–scoped data
// --------------------------------------------

export const auditSchemaWithOrganization = {
  // Organization reference
  organizationId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Tenant", // Reference model for organizations
    required: true,
    index: true,
  },

  // Audit fields
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },

  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },

  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },

  deletedAt: {
    type: Date,
    default: null,
  },
  isDeleted: {
    type: Boolean,
    default: false
  }
};

// ----------------------------------------------------
// 2. Audit schema for global (non-organization) data
// ----------------------------------------------------
export const auditSchemaWithoutOrganization = {
  // Audit fields
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },

  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },

  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },

  deletedAt: {
    type: Date,
    default: null,
  },
  isDeleted: {
    type: Boolean,
    default: false
  }
};

// Alias exports for clean naming in models
export const AuditWithOrganization = auditSchemaWithOrganization;
export const AuditWithoutOrganization = auditSchemaWithoutOrganization;