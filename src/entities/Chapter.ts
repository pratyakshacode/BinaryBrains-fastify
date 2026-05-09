import { 
    BaseEntity, 
    Column, 
    CreateDateColumn, 
    Entity, 
    JoinColumn, 
    ManyToOne, 
    PrimaryGeneratedColumn, 
    UpdateDateColumn 
} from "typeorm";
import { User } from "./User";

@Entity('chapters')
export class Chapter extends BaseEntity {
    
    @PrimaryGeneratedColumn("uuid")
    id!: string;
    
    @Column()
    title!: string;

    @Column({ type: 'longtext' })
    description!: string;

    @Column({ type: 'json' })
    sectionIds: string[] = [];

    // Allows instructors to share chapters across the organization or keep them private
    @Column({ default: false })
    isPublic!: boolean;

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