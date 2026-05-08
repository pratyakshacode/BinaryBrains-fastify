import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  JoinColumn,
  Index
} from 'typeorm';
import { UserRoleMap } from './UserRoleMap';
import { Organization } from './Organization';
import { AuditBaseEntityWithoutOrg } from './AuditBaseEntity';

export enum UserRole {
  ADMIN = "admin",
  STUDENT = "student",
  TRAINER = "trainer",
}

@Entity()
@Index(['email', 'organization'])
export class User extends AuditBaseEntityWithoutOrg {
  
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column({ type: 'varchar', length: 100 })
  firstName!: string;

  @Column({ type: 'varchar', length: 100 })
  lastName!: string;

  @Column()
  userName!: string;

  @Column({ type: 'varchar', length: 150})
  email!: string;

  @Column({ type: 'varchar', length: 255 })
  password!: string;

  @Column({ default: '' })
  avatar!: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.STUDENT
  })
  role!: UserRole;

  @Column({ nullable: true })
  token!: string;

  @ManyToOne(() => Organization, (org) => org.users)
  @JoinColumn({ }) 
  organization!: Organization;

  @Column({ default: '' })
  googleId!: string;

  @Column({ type: 'longtext' })
  refreshToken!: string;

  @OneToMany(() => UserRoleMap, (userRoleMap) => userRoleMap.user)
  userRoleMaps!: UserRoleMap[];

  @Column({ type: 'boolean', default: true })
  isActive!: boolean;

}