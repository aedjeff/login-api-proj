import * as dotenv from "dotenv";
dotenv.config();

const { URI, PORT, SECRET_ACCESS_TOKEN, EMAIL_USERNAME, PASSWORD } = process.env;

export { URI, PORT, SECRET_ACCESS_TOKEN, EMAIL_USERNAME, PASSWORD };