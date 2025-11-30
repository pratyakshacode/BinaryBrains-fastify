// File contains the relationship map between user and organization

import {
  Entity,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from "typeorm";
import { User } from "./User";
import { Organization } from "./Organization";
import { AuditBaseEntityWithoutOrg } from "./AuditBaseEntity"; 

@Entity()
@Index(['user', 'organization'], { unique: true })
export default class UserOrganizationMap extends AuditBaseEntityWithoutOrg {

  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @ManyToOne(() => User, { nullable: false })
  @JoinColumn({ name: "userId" })
  user!: User;

  @ManyToOne(() => Organization, { nullable: false })
  @JoinColumn({ name: "organizationId" })
  organization!: Organization;
  
}