import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn, 
  UpdateDateColumn,
  ManyToOne,
  OneToMany,
  JoinColumn,
  BaseEntity
} from 'typeorm';
import { User } from './User';
import { ArticleReaction } from './ArticleReaction';

@Entity('articles')
export class Article extends BaseEntity {
  
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  title!: string;

  @Column({ type: 'varchar', length: 500, nullable: true })
  description!: string; 

  @Column({ type: 'text' })
  content!: string;

  @Column({ type: 'boolean', default: false })
  isDeleted!: boolean;

  @Column({ 
    type: 'enum', 
    enum: ['draft', 'published', 'archived'],
    default: 'draft' 
  })
  status!: string;

  // ---------------------------------------------------
  // The Foreign Key Relationship to User
  // ---------------------------------------------------
  @ManyToOne(() => User)
  @JoinColumn({ name: 'createdById' }) // Tells TypeORM the exact column name
  createdBy!: User;

  // ---------------------------------------------------
  // Like & Dislike System (Cached Counts)
  // ---------------------------------------------------
  @Column({ type: 'int', default: 0 })
  likeCount!: number;

  @Column({ type: 'int', default: 0 })
  dislikeCount!: number;

  // Relation to the exact user interactions
  @OneToMany(() => ArticleReaction, (reaction) => reaction.article)
  reactions!: ArticleReaction[];

  // ---------------------------------------------------
  // Audit Timestamps
  // ---------------------------------------------------
  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}