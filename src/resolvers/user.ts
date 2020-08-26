import { Resolver, Mutation, InputType, Field, Ctx, Arg, ObjectType } from 'type-graphql';
import { User } from '../entities/User';
import { MyContext } from '../types'
import argon2 from 'argon2';

@InputType()
class UsernamePasswordInput{
    @Field()
    username: string
    @Field()
    password: string
}

@ObjectType()
class FieldError{
    @Field()
    field: string;

    @Field()
    message: string;
}

@ObjectType()
class UserResponse {
    @Field(() => [FieldError], {nullable: true})
    errors?: FieldError[];

    @Field(() => User, {nullable: true})
    user?: User;
}

@Resolver()
export class UserResolver {
    @Mutation(() => UserResponse)
    async register(
        @Arg('options') options: UsernamePasswordInput,
        @Ctx() { em }: MyContext
    ): Promise<UserResponse>{  
        if (options.username.length <= 2) {
            return {
                errors: [{
                    field: 'username',
                    message: "lenght must be greater than 2"
                }]
            }
        }
        if (options.password.length <= 2) {
            return {
                errors: [{
                    field: 'password',
                    message: "lenght must be greater than 2"
                }]
            }
        }
        const hashPassword = await argon2.hash(options.password)
        const user = em.create(User,{username: options.username , password: hashPassword})
        
        try{
            await em.persistAndFlush(user)
        } catch(err){
            if(err.code === '23505' || err.detail.includes('already exists')){
                return {
                    errors: [
                        {
                            field: 'username',
                            message: 'username already taken',
                        },
                    ]
                }
            }
        }    
        return {user};
    }

    @Mutation(() => UserResponse)
    async login(
        @Arg('options') options: UsernamePasswordInput,
        @Ctx() { em, req }: MyContext
    ): Promise<UserResponse>{  
        const user = await em.findOneOrFail(User, {username: options.username});
        if(!user){
            return{
                errors: [{
                    field: 'username',
                    message: 'that username doesnt exist',
                },
            ],
            }
        }
        const valid = await argon2.verify(user.password, options.password)
        if(!valid){
            return{
                errors: [{
                    field: 'password',
                    message: 'password does not match',
                },
                ],
            }
        }

        req.session.userId = user.id;

        return {
            user,
        };
        
    }

}