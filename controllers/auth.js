import { db } from "../connect.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const register = (req, res) => {

  //CHECK USER IF EXISTS

  const q = "SELECT * FROM users WHERE username = ?";

  db.query(q, [req.body.username], (err, data) => {
    if(err) return res.status(500).json(err);
    if(data.length) return res.status(409).json("User already exists!");

  //CREATE A NEW USER
    //Hash the password. 
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(req.body.password, salt);   
    
    const q = 
      "INSERT INTO users (username, email, password, name) VALUE (?)";

    const values = [
      req.body.username, 
      req.body.email, 
      hashedPassword, 
      req.body.name
    ];

    db.query(q, [values], (err, data) => {
      if(err) return res.status(500).json(err);
      return res.status(200).json("User has been created.");
    });
  });
};

export const login = (req, res) => {

  const q = "SELECT * FROM users WHERE username = ?";

  db.query(q, [req.body.username], (err, data) => {
    if (err) return res.status(500).json(err);
    if (data.length === 0) return res.status(404).json("User not found!");

    const checkPassword = bcrypt.compareSync(
      req.body.password, 
      data[0].password 
    );

    if(!checkPassword) 
      return res.status(400).json("Wrong password or username!");

    const token = jwt.sign({ id:data[0].id }, "secretkey");

    const { password, ...others } = data[0];

    res.cookie("accessToken", token, {
      httpOnly: true,  
    }).status(200).json(others);

    // The alternative below certifies that the cookie will be active for 1 year (test it when possible)
    /* res.cookie("accessToken", token, {
      httpOnly: true,
      expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // Set expiration to one year from now
    }).status(200).json(others); */
  });
  
};

export const logout = (req, res) => {
  res.clearCookie("accessToken", {
    secure: true,
    sameSite: "none"
  }).status(200).json("User has been logged out.");
};

/* HASHING A PASSWORD: 

During registration:
- The application generates a random salt.
- The plaintext password is concatenated with the salt.
- The combined salt and password are hashed using a secure hashing algorithm, resulting in a hashed password.
- Both the hashed password and the salt are stored in the database.

During login:
- When a user attempts to log in, they provide their plaintext password.
- The application retrieves the corresponding salt from the user's stored data in the database.
- The application concatenates the provided password with the retrieved salt.
- The combined salt and password are hashed using the same hashing algorithm used during registration.
- The resulting hash is compared to the stored hashed password in the database.
- If the hashes match, the login attempt is successful; otherwise, it fails. 

Here's why hashing passwords is important and how it's typically done in web applications:

Security: Storing passwords in plaintext format is a significant security risk. If an attacker gains unauthorized access to the database, 
they could easily retrieve all the passwords and potentially compromise user accounts on your application. Hashing passwords helps mitigate 
this risk because even if an attacker accesses the hashed passwords, they are extremely difficult to reverse-engineer back to the original 
plaintext passwords.

Hashing Algorithm: Web applications typically use cryptographic hashing algorithms like bcrypt, SHA-256, or Argon2 to hash passwords. 
These algorithms are designed to be computationally expensive, making it difficult for attackers to perform brute-force or dictionary 
attacks to crack hashed passwords.

Salting: To further enhance security, a random value called a "salt" is often added to the password before hashing. 
The salt is stored alongside the hashed password in the database. Salting prevents attackers from using precomputed tables (rainbow tables) 
to crack hashed passwords efficiently, as each hashed password will have a unique salt. Furthermore, a salt is a unique identifier for 
each password, so even if two users have the exact same password, we'll be able to identify the correct user.

*/