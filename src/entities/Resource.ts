import { Entity, PrimaryGeneratedColumn, Column, OneToMany, BaseEntity, CreateDateColumn, UpdateDateColumn, JoinColumn, ManyToOne } from "typeorm"
import { User } from "./User"
import { Policy } from "./Policy"

@Entity()
export class Resource extends BaseEntity {
    @PrimaryGeneratedColumn("uuid")
    id!: string

    @Column({ unique: true })
    name!: string

    @Column()
    description!: string

    @OneToMany(() => Policy, (policy) => policy.resource)
    public policies!: Policy[]

    @Column({
        type: "tinyint",
        default: 0,
    })
    isDeleted!: boolean

    @ManyToOne(()=>User, {nullable: true, onDelete: "NO ACTION"})
    @JoinColumn()
    createdBy!: User

    @CreateDateColumn()
    createdAt!: Date

    @ManyToOne(()=>User, {nullable: true, onDelete: "NO ACTION"})
    @JoinColumn()
    updatedBy!: User

    @UpdateDateColumn()
    updatedAt!: Date
}
