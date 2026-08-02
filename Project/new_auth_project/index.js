//API PLANNING

// Register : POST -> /register  -> Adding new user
// Login : POST -> /login  -> Email, pass
// Refresh : POST -> /refresh


const express = require('express');
const bcrypt = require('bcrypt');
const { PrismaClient } = require("@prisma/client");
const jwt = require('jsonwebtoken');

const app = express();
const prisma = new PrismaClient();

app.use(express.json());



const PORT = 8000;

app.listen(PORT, () => {
    console.log("Server is running on port : ", PORT)
});


app.get("/", (req, res) => {
    res.send("Vanakam da mapla")
});


// Register
app.post("/register", async (req, res) => {
    try {
        // Data from frontend
        const new_data = req.body;

        // DB logic
        const isUserExists = await prisma.users.findUnique({
            where: { email: new_data.email },
        });

        if (isUserExists) {
            //401 -> Unauthorised access
            return res.status(409).json({ message: "User already exists" });
        }




        //Hashing Password:
        const hashedPassword = await bcrypt.hash(new_data.password, 10);

        const newUser = await prisma.users.create({
            data: {
                name: new_data.name,
                email: new_data.email,
                password: hashedPassword,
                phone_number: new_data.phone_number,
            }
        });

        // REMOVING PASSWORD FROM RESPONSE
        const { password, ...dataForFrontend } = newUser;

        // Data to frontend
        res.status(201).json({ message: "User created successfully", data: dataForFrontend });

    } catch (err) {
        console.log("INTERNAL SERVER ERROR", err);
        res.status(500).json({ message: "Internal Server Error", error: err.message });
    }

});

// Login
app.post("/login", async (req, res) => {
    try {
        //Data from frontend 
        const data = req.body;

        // DB logic
        const isUserExist = await prisma.users.findUnique({
            where: { email: data.email }
        });


        if (isUserExist) {

            //bcrypt.compare() -> returns boolean
            const isPasswordValid = await bcrypt.compare(data.password, isUserExist.password)

            if (isPasswordValid) {

                //Login success -> So give them the JWT token (Main_key and temp_key)
                var temp_key = jwt.sign({ user_id: isUserExist.user_id, email: isUserExist.email }, "temp_key_secret_code", { expiresIn: "20s" });
                var main_key = jwt.sign({ user_id: isUserExist.user_id, email: isUserExist.email }, "main_key_secret_code", { expiresIn: "30s" })
                res.status(200).json({ message: "User logged in successfully", tokens: { temp_key, main_key } });

            } else { res.status(401).json({ message: "Inncorrect Password" }); }

        } else {
            res.status(404).json({ message: "Email not found" });

            //IN PRODUCTION: LINE 96 AND LINE 99 NUST RETURN SAME MESSAGE "401: Invalid email or password" TO PREVENT BOT ATTACKS.
        }

    } catch (err) {
        console.log("INTERNAL SERVER ERROR", err);
        res.status(500).json({ message: "INTERNAL SERVER ERROR", error: err.message });
    }

});
