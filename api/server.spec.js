const request = require('supertest');

const server = require('./server');
const db = require('../database/dbConfig');
const Users = require('../users/users-model');

describe('server.js', () => {
    it('should set testing environment', () => {
        expect(process.env.DB_ENV).toBe('testing');
    });

    describe('User model', () => {
        it('should insert user', async () => {
            await Users.add({username:"ash", password: "password"});
            const users = await db('users');
            expect(users).toHaveLength(1);
        });

        it('should delete user', async () => {
            await Users.remove(1)
            const users = await db('users');
            expect(users).toHaveLength(0);
        });

    });
    describe('login', () => {
        const user = {
            username: "IanMichael",
            password: "password"
        };

        it('should return json', async () => {
            const res = await request(server).post('/api/auth/login').send(user);
            expect(res.type).toBe('application/json');
        });

    })
    describe('GET Jokes', () => {
        it('should return a status of 401 when not logged in', async () => {
            const res = await request(server).get('/api/jokes');
            expect(res.status).toBe(401);
        });

        it('should return json', async () => {
            const res = await request(server).get('/api/jokes');
            expect(res.type).toBe('application/json');
        });
    })
});

beforeEach(async () => {
    await db('users').truncate();      
});