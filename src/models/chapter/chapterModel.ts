import mongoose, { Schema, Document } from "mongoose";

/**
 * Chapter Model
 * ---------------------
 * This file defines the Mongoose schema and model for "Chapter".
 * 
 * Each chapter contains:
 *  - title:        Title of the chapter
 *  - description: Short summary of what the chapter covers
 *  - resources:   A list of linked learning resources such as articles,
 *                  questions, videos, PDFs, etc.
 * 
 * Note:
 *  Resources do NOT reference Mongo ObjectIds. Instead, each resource
 *  points to an external entity stored in SQL using a UUID.
 * 
 * This model is used to map chapter metadata stored in MongoDB while
 * maintaining references to SQL-based learning assets.
 */

export interface ChapterResource {
  type: "article" | "challenge" | "video" | "mcq";
  title: string;
  id: string; // UUID from SQL
}

export interface Chapter extends Document {
  title: string;
  description: string;
  resources: ChapterResource[];
}

const resourceSchema = new Schema<ChapterResource>(
  {
    type: {
      type: String,
      enum: ["article", "challenge", "video", "mcq"],
      required: true,
    },
    title: {
      type: String,
      required: true,
    },
    id: {
      type: String, // UUID from SQL
      required: true,
    },
  },
  { _id: false }
);

const chapterSchema = new Schema<Chapter>(
  {
    title: { type: String, required: true },
    description: { type: String, required: true },
    resources: { type: [resourceSchema], default: [] },
  },
  { timestamps: true }
);

export const Chapter = mongoose.model<Chapter>("Chapter", chapterSchema);