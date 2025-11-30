import mongoose, { Schema } from 'mongoose';
import { AuditWithOrganization } from '../authorization/auditSchema';

/**
 * Instructor Sub-Schema
 * ---------------------
 * Contains instructor-related metadata.
 * All fields are optional.
 */

const instructorSchema = new Schema(
  {
    name: {
      type: String,
      trim: true,
    },
    experience: {
      type: String, // e.g., "5 years", "Senior Developer"
      trim: true,
    },
    description: {
      type: String,
      trim: true,
    },
    photoUrl: {
      type: String,
      default: "",
      trim: true,
    },
  },
  { _id: false } // avoids creating _id for each instructor object
);

/**
 * Course Schema
 * ---------------------
 * Stores course metadata, pricing, tags, instructors, and status.
 */
const courseSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    backgroundURL: {
      type: String,
      default: "",
      trim: true,
    },
    duration: {
      type: Number,
      default: 0,
    },
    type: {
      type: String,
      enum: ['free', 'paid'],
      default: 'free',
    },
    amount: {
      type: Number,
      default: 0,
    },
    tags: [
      {
        type: String,
        trim: true,
      },
    ],
    status: {
      type: String,
      enum: ['draft', 'published'],
      default: 'draft',
    },
    archived: {
      type: Boolean,
      default: false,
    },
    instructor: {
      type: [instructorSchema], // multiple instructors allowed
      default: [],
    },
    rating: {
      type: Number,
      min: 1,
      max: 5,
      default: 3
    },
  },
  { timestamps: true }
);

courseSchema.add(AuditWithOrganization);

export const Course = mongoose.model('Course', courseSchema);