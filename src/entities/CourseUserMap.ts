import { 
    Entity, 
    PrimaryGeneratedColumn, 
    Column, 
    BaseEntity, 
    CreateDateColumn, 
    UpdateDateColumn, 
    ManyToOne, 
    JoinColumn, 
    Index 
} from "typeorm";
import { User } from "./User";
import { Course } from "./Course";

@Entity()
@Index(['userId', 'courseId'], { unique: true }) // Crucial: Prevents duplicate enrollments
export class CourseUserMap extends BaseEntity {

    @PrimaryGeneratedColumn('uuid')
    id!: string;

    @Column()
    userId!: string;

    @Column()
    courseId!: string;

    // To track overall progress (0 to 100)
    @Column({ type: 'int', default: 0 })
    progress!: number;

    // Array of resource IDs the user has completed
    @Column({ type: 'simple-array' })
    completedResources!: string[];

    // Optional relationships if you need to JOIN tables later
    @ManyToOne(() => User)
    @JoinColumn({ name: 'userId' })
    user!: User;

    @ManyToOne(() => Course)
    @JoinColumn({ name: 'courseId' })
    course!: Course;

    @CreateDateColumn()
    enrolledAt!: Date;

    @UpdateDateColumn()
    updatedAt!: Date;
}