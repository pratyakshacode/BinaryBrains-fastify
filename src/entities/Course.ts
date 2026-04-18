import { 
    Entity, 
    PrimaryGeneratedColumn, 
    Column, 
    BaseEntity, 
    CreateDateColumn, 
    UpdateDateColumn 
} from "typeorm";

export enum CourseType {
    FREE = 'free',
    PAID = 'paid'
}

export enum CourseStatus {
    DRAFT = 'draft',
    PUBLISHED = 'published'
}

@Entity()
export class Course extends BaseEntity {

    @PrimaryGeneratedColumn('uuid')
    id!: string;

    @Column({ type: 'varchar', length: 255 })
    title!: string;

    @Column({ type: 'text' })
    description!: string;

    @Column({ type: 'varchar', default: '' })
    backgroundURL!: string;

    @Column({ type: 'int', default: 0 })
    duration!: number;

    @Column({ type: 'enum', enum: CourseType, default: CourseType.FREE })
    type!: CourseType;

    @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
    amount!: number;

    @Column({ type: 'simple-array', default: '' })
    tags!: string[];

    @Column({ type: 'enum', enum: CourseStatus, default: CourseStatus.DRAFT })
    status!: CourseStatus;

    @Column({ type: 'boolean', default: false })
    archived!: boolean;

    @Column({ type: 'json' })
    instructors: any[] = []; 

    @Column({ type: 'float', default: 3.0 })
    rating!: number;

    @Column({ type: 'json' })
    curriculumTree: any[] = [];

    @Column({ type: 'varchar', nullable: true })
    createdBy!: string;

    @Column({ type: 'varchar', nullable: true })
    updatedBy!: string;

    @CreateDateColumn()
    createdAt!: Date;

    @UpdateDateColumn()
    updatedAt!: Date;
}