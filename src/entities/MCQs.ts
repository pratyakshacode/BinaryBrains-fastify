import { BaseEntity, Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
import { User } from "./User";

export enum MCQType {
    SINGLE_CHOICE = 'SINGLE_CHOICE',
    MULTI_SELECT = 'MULTI_SELECT',
    TRUE_FALSE = 'TRUE_FALSE'
}

@Entity()
export class Mcq extends BaseEntity {

    @PrimaryGeneratedColumn("uuid")
    id!: string;

    @Column()
    title!: string;

    @Column({ type: "longtext", nullable: true })
    explanation!: string;

    // ENUM: 'SINGLE_CHOICE', 'MULTI_SELECT', 'TRUE_FALSE'
    @Column({ type: "enum", enum: MCQType })
    type!: MCQType;

    // Store as JSON array: ["Option A", "Option B", "Option C"] or ["True", "False"]
    @Column("json")
    options!: string[]; 

    // For MULTI_SELECT, this could be a JSON array of the correct answers
    @Column("json")
    correctAnswer!: string[]; 

    @Column({ default: false })
    isPublic!: boolean
    
    @Column({ default: false })
    isDeleted!: boolean;

    @ManyToOne(() => User)
    @JoinColumn()
    createdBy!: User;

    @CreateDateColumn()
    createdAt!: Date;

    @UpdateDateColumn()
    updatedAt!: Date;

}