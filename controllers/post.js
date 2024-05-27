import {db} from "../connect.js";
import jwt from "jsonwebtoken";
import moment from "moment";

export const getPosts = (req, res) => {

  const userId = req.query.userId;
  const token = req.cookies.accessToken;
 
  if(!token) return res.status(401).json("Not logged in!");

  jwt.verify(token, "secretkey", (err, userInfo) => {
    if(err) return res.status(403).json("Token is not valid!");

    // Não entendi porque eu selecionaria uma query alternativa para o caso de ter um userId inválido / não definido
    const q = userId !== "undefined"
      ? 'SELECT p.*, u.id AS userId, name, profilePic FROM posts AS p JOIN users AS u ON (u.id = p.userId) WHERE p.userId = ? ORDER BY p.createdAt DESC' 
      : 'SELECT p.*, u.id AS userId, name, profilePic FROM posts AS p JOIN users AS u ON (u.id = p.userId) ' +
        'LEFT JOIN relationships AS r ON (p.userId = r.followedUserId) WHERE r.followerUserId = ? OR p.userId = ? ' +
        'ORDER BY p.createdAt DESC';

    const values = 
      userId !== "undefined" ? [userId] : [userInfo.id, userInfo.id]; 

    db.query(q, values, (err, data) => {
        if(err) return res.status(500).json(err);

        // Check for duplicates
        const uniquePosts = [];
        const postIds = new Set();

        data.forEach((post) => {
          if (!postIds.has(post.id)) {
            uniquePosts.push(post);
            postIds.add(post.id);
          }
        }); 

        //console.log("Unique posts:", uniquePosts); // Log unique posts

        return res.status(200).json(uniquePosts);
    });
  });
};

export const addPost = (req, res) => {

  const token = req.cookies.accessToken;
  if(!token) return res.status(401).json("Not logged in!");

  jwt.verify(token, "secretkey", (err, userInfo) => { 
    if(err) return res.status(403).json("Token is not valid!");

    const q = "INSERT INTO posts (`desc`, `img`, `userId`, `createdAt`) VALUES (?)";

    const values = [
      req.body.desc,
      req.body.img,
      userInfo.id,
      moment(Date.now()).format("YYYY-MM-DD HH:mm:ss")
    ]

    db.query(q, [values], (err, data) => {
        if(err) return res.status(500).json(err);
        return res.status(200).json("Post has been created.");
    });
  });
};

export const deletePost = (req, res) => {

  const token = req.cookies.accessToken;
  if(!token) return res.status(401).json("Not logged in!");

  jwt.verify(token, "secretkey", (err, userInfo) => {
    if(err) return res.status(403).json("Token is not valid!");

    // Delete comments associated with the post being deleted
    const deleteCommentsQuery = "DELETE FROM comments WHERE postId = ?";
    db.query(deleteCommentsQuery, [req.params.id], (err, commentData) => {
      if(err) return res.status(500).json(err);

      // Once comments are deleted, proceed to delete the post
      const deletePostQuery = "DELETE FROM posts WHERE id = ? AND userId = ?";
      db.query(deletePostQuery, [req.params.id, userInfo.id], (err, postData) => {
        if(err) return res.status(500).json(err);
        if(postData.affectedRows > 0) {
          return res.status(200).json("Post and associated comments have been deleted.");
        } else {
          return res.status(403).json("You can delete only your post.");
        }
      });
    });
  });
};


/*

export const getPosts = (req, res) => {

- This exports a function named getPosts, which handles GET requests to fetch posts from the database. 
  It takes req (request) and res (response) objects as parameters, which represent the incoming HTTP request 
  and the outgoing HTTP response, respectively.

const userId = req.query.userId;
const token = req.cookies.accessToken;

if(!token) return res.status(401).json("Not logged in!");

jwt.verify(token, "secretkey", (err, userInfo) => {
  if(err) return res.status(403).json("Token is not valid!");

- These lines extract the userId from the query parameters of the request (req.query.userId) and the access token 
  from the cookies (req.cookies.accessToken). 
- If there's no access token (!token), it returns a 401 Unauthorized response.
- It then verifies the JWT token (jwt.verify) using a secret key ("secretkey"). If the token is not valid (err), 
  it returns a 403 Forbidden response.

console.log(userId);

const q = userId !== "undefined"
  ? 'SELECT p.*, u.id AS userId, name, profilePic FROM posts AS p JOIN users AS u ON (u.id = p.userId) WHERE p.userId = ? ORDER BY p.createdAt DESC' 
  : 'SELECT p.*, u.id AS userId, name, profilePic FROM posts AS p JOIN users AS u ON (u.id = p.userId) ' +
    'LEFT JOIN relationships AS r ON (p.userId = r.followedUserId) WHERE r.followerUserId = ? OR p.userId = ? ' +
    'ORDER BY p.createdAt DESC';

const values = 
  userId !== "undefined" ? [userId] : [userInfo.id, userInfo.id];
    
- These lines construct a SQL query (q) based on whether a userId is provided in the request.
- If a userId is provided, it selects posts authored by that user (p.userId = ?). Otherwise, it selects posts 
  from users followed by the logged-in user or posts from the logged-in user (r.followerUserId = ? OR p.userId = ?).
- It also specifies the values to be used in the query based on whether a userId is provided.

    db.query(q, values, (err, data) => {
        if(err) return res.status(500).json(err);
        return res.status(200).json(data);
    });
  });
};

- This executes the SQL query (db.query) using the constructed query string (q) and values. It then sends 
  the result (data) as a JSON response with a status code of 200 OK. If there's an error (err), it returns 
  a 500 Internal Server Error response.

 The getPosts function retrieves posts from the database based on the provided userId or the logged-in user's followings, 
 verifies the authentication token, constructs and executes the SQL query, and sends the result back to the client 
 as a JSON response.

- Access tokens primarily serve security purposes within a system. While userIds uniquely identify users, 
  they don't inherently provide security against unauthorized access or malicious activities.
*/ 
