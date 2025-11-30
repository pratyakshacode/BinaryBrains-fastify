import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToMany,
  Index,
  OneToOne,
  JoinColumn
} from 'typeorm';
import { User } from './User';
import { AuditBaseEntityWithoutOrg } from './AuditBaseEntity';

@Entity()
@Index(['title'], { unique: true })
export class Organization extends AuditBaseEntityWithoutOrg {
  
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column()
  title!: string;

  @Column()
  description!: string;

  @OneToMany(() => User, (user) => user.organization)
  users!: User[];

  @OneToOne(() => User, { nullable: true })
  @JoinColumn()
  owner: User

}