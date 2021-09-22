export interface User {
    nickname: string,
    _id: string,
    groupId: string,
    year: number,
    time: number,
    verified?: boolean,
    avatar?: string
}