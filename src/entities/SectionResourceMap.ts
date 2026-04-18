import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn, CreateDateColumn, BaseEntity, UpdateDateColumn, Index } from 'typeorm';
import { Section } from './Section';
import { User } from './User';

export enum ResourceType {
    MCQ = 'mcq',
    VIDEO = 'video',
    ARTICLE = 'article'
}

@Entity()
@Index(['sectionId', 'orderIndex'], { unique: true })
export class SectionResourceMap extends BaseEntity {

    @PrimaryGeneratedColumn('uuid')
    id!: string;

    @Column()
    sectionId!: string

    @Column()
    resourceId!: string

    @Column()
    resourceTitle!: string

    @Column({ type: 'enum', enum: ResourceType })
    resourceType!: ResourceType

    @Column({ type: 'int' })
    orderIndex!: number; 

    @ManyToOne(() => User)
    @JoinColumn()
    createdBy!: User;

    @ManyToOne(() => User)
    @JoinColumn()
    updatedBy!: User;

    @CreateDateColumn()
    createdAt!: Date

    @UpdateDateColumn()
    updatedAt!: Date

}