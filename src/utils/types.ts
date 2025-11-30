/**
 * File contains the types to be used all over the app
 */
interface TokenPayload {
    id: string;
    role: string;
    email: string;
    organizationId: string;
}

interface SignUpBody {
    email: string;
    password: string;
    userName: string;
    role: string;
    firstName: string;
    lastName: string;
}
