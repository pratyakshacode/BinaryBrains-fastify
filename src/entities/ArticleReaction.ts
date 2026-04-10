import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  ManyToOne, 
  JoinColumn, 
  Unique, 
  CreateDateColumn 
} from 'typeorm';
import { User } from './User';
import { Article } from './Article';

@Entity('article_reactions')
// CRITICAL: This composite unique index ensures a user can only have ONE reaction per article
@Unique(['userId', 'articleId']) 
export class ArticleReaction {
  
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  // Track whether they liked or disliked it
  @Column({ type: 'enum', enum: ['like', 'dislike'] })
  type!: 'like' | 'dislike';

  // The User who reacted
  @ManyToOne(() => User)
  @JoinColumn({ name: 'userId' })
  user!: User;

  @Column({ type: 'uuid' })
  userId!: string;

  // The Article they reacted to
  @ManyToOne(() => Article, (article) => article.reactions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'articleId' })
  article!: Article;

  @Column({ type: 'uuid' })
  articleId!: string;

  @CreateDateColumn()
  createdAt!: Date;
}