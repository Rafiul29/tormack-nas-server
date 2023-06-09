const express=require('express');
const {signupUser,loginUser,getUser,deleteUser,updateUser,getUsers}=require("../controllers/user");
const authMiddleware = require('../middlewares/auth.middlewares');
const isAdmin=require('../middlewares/admin.middleware')

//router
const router=express.Router();

//login route
router.post('/login',loginUser);

//signup route
router.post('/signup',signupUser);

// //get all users
router.get("/all",authMiddleware,isAdmin,getUsers)

//get an user
router.get("/:userId",authMiddleware,getUser)

// //update an user
router.patch("/:userId",authMiddleware,updateUser)

// //delete an user
router.delete("/:userId",authMiddleware,deleteUser)

module.exports=router