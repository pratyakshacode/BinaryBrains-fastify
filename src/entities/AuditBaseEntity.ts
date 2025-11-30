import { BaseEntity, Column, CreateDateColumn, JoinColumn, ManyToOne, UpdateDateColumn } from "typeorm";
import { User } from "./User";
import { Organization } from "./Organization";


export abstract class AuditBaseEntity extends BaseEntity {
  @Column({ default: false })
  isDeleted!: boolean;

  @ManyToOne(() => User, { nullable: true })
  createdBy!: User | null;

  @ManyToOne(() => User, { nullable: true })
  updatedBy!: User | null;

  @ManyToOne(() => Organization, { nullable: true })
  organization!: Organization | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}

export abstract class AuditBaseEntityWithoutOrg extends BaseEntity {
  @Column({ default: false })
  isDeleted!: boolean;

  @ManyToOne(() => User, { nullable: true })
  createdBy!: User | null;

  @ManyToOne(() => User, { nullable: true })
  updatedBy!: User | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
