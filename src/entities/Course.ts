import { 
    Entity, 
    PrimaryGeneratedColumn, 
    Column, 
    BaseEntity, 
    CreateDateColumn, 
    UpdateDateColumn, 
    ManyToOne,
    JoinColumn
} from "typeorm";
import { User } from "./User";

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

    // FIX: Removed 'default: []' from decorator. Initialized via class property.
    @Column({ type: 'simple-array' })
    tags: string[] = [];

    @Column({ type: 'enum', enum: CourseStatus, default: CourseStatus.DRAFT })
    status!: CourseStatus;

    @Column({ type: 'boolean', default: false })
    archived!: boolean;

    @Column({ type: 'json' })
    instructors: any[] = []; 

    @Column({ type: 'float', default: 3.0 })
    rating!: number;

    // FIX: Removed 'default: []' from decorator. MySQL JSON columns can't have defaults.
    @Column({ type: 'json' })
    curriculumTree: any[] = [];

    @ManyToOne(() => User)
    @JoinColumn({ name: 'createdById' }) 
    createdBy!: User;

    @ManyToOne(() => User)
    @JoinColumn({ name: 'updatedById' }) 
    updatedBy!: User;

    // FIX: Removed 'default: new Date()'. @CreateDateColumn handles this automatically.
    @CreateDateColumn()
    createdAt!: Date;

    // FIX: Removed 'default: new Date()'. @UpdateDateColumn handles this automatically.
    @UpdateDateColumn()
    updatedAt!: Date;
}