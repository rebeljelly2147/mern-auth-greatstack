import mongoose from 'mongoose';

const connectDB = async () => {
    mongoose.connection.on('connected', () => {
        console.log('DB connected');
    });
    mongoose.connection.on('error', (err) => {
        console.log('DB connection error:', err);
    });
    await mongoose.connect(`${process.env.MONGODB_URI}/mern-auth-greatstack`);
}

export default connectDB;