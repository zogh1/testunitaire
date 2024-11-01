const request = require('supertest');
const { app } = require('../server');
const User = require('../models/User');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

let mongoServer;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  await mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });
});

afterEach(async () => {
  await User.deleteMany({});
});

afterAll(done => {
  // Closing the DB connection allows Jest to exit successfully.
  mongoose.connection.close()
  done()
})

describe('User Controller Tests', () => {
  it('should register a new user', async () => {
    const newUser = {
      name: 'Jane Doe',
      email: 'jane@example.com',
      password: 'password123',
      role: 'User',
      organization: 'Test Org',
      position: 'Test Position',
      phone: '0123456789',
      location: 'Test Location',
      specialization: 'Test Spec',
    };

    const response = await request(app).post('/api/users/register').send(newUser);
    expect(response.status).toBe(201);
    expect(response.body).toHaveProperty('msg', 'User registered. Please check your email for verification.');
  });

  it('should return 400 if user already exists', async () => {
    const existingUser = {
      name: 'Jane Doe',
      email: 'jane@example.com',
      password: 'password123',
      role: 'User',
      organization: 'Test Org',
      position: 'Test Position',
      phone: '0123456789',
      location: 'Test Location',
      specialization: 'Test Spec',
    };

    // Create an initial user
    await new User(existingUser).save();

    // Attempt to register the same user again
    const response = await request(app).post('/api/users/register').send(existingUser);

    expect(response.status).toBe(400);
    expect(response.body.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          msg: 'This email address is already in use',
        }),
      ])
    );
  });

  it('should verify the email', async () => {
    const newUser = {
      name: 'Jane Doe',
      email: 'jane@example.com',
      password: 'password123',
      role: 'User',
      organization: 'Test Org',
      position: 'Test Position',
      phone: '0123456789',
      location: 'Test Location',
      specialization: 'Test Spec',
    };

    // Register the user
    const registerResponse = await request(app).post('/api/users/register').send(newUser);
    expect(registerResponse.status).toBe(201);

    // Simulate email verification
    const { verificationToken } = await User.findOne({ email: newUser.email });
    const verifyResponse = await request(app).get(`/api/users/verify/${verificationToken}`);

    expect(verifyResponse.status).toBe(200);
    expect(verifyResponse.body).toHaveProperty('msg', 'Email verified successfully. You can now login.');
  });

  it('should return 400 if required fields are missing', async () => {
    const incompleteUser = {
      name: 'Jane Doe',
      email: 'jane@example.com',
      password: 'password123',
      role: 'User',
    };

    const response = await request(app).post('/api/users/register').send(incompleteUser);
    expect(response.status).toBe(400);
    expect(response.body.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          msg: 'Organization is required',
        }),
        expect.objectContaining({
          msg: 'Position is required',
        }),
        expect.objectContaining({
          msg: 'Phone number is required',
        }),
        expect.objectContaining({
          msg: 'Location is required',
        }),
        expect.objectContaining({
          msg: 'Specialization is required',
        }),
      ])
    );
  });
});
