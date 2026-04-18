import { BaseEntity, Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, OneToMany, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
import { User } from "./User";
import { SectionResourceMap } from "./SectionResourceMap";

export enum SectionType {
    ORDINARY = 'ordinary',
    MCQ = 'mcq'
}

@Entity()
export class Section extends BaseEntity {
    
    @PrimaryGeneratedColumn("uuid")
    id!: string
    
    @Column()
    title!: string

    @Column({ type: 'longtext', default: "" })
    description!: string
    
    @Column({
        type: "enum",
        enum: SectionType

    })
    type!: SectionType

    @Column({ default: false })
    isPublic!: boolean

    @Column({ default: false })
    isDeleted!: boolean

    @ManyToOne(() => User)
    @JoinColumn()
    createdBy!: User

    @CreateDateColumn()
    createdAt!: Date

    @UpdateDateColumn()
    updatedAt!: Date

}