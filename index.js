require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const userRoutes=require('./routes/user')
const deviceRoutes=require('./routes/device')
//express app
const app=express()
//middlewares
app.use(
  cors({
    credentials: true,
  })
);

app.use(express.json());


//routes
app.get('/',(req,res)=>{
  res.status(200).json({message:"welcome to Tormack server"})
})

app.use('/api/auth/user',userRoutes)

app.use('/api/data/device',deviceRoutes)

const port= process.env.PORT || 8080


const uri=process.env.MONGO_URI

//mongoose 
mongoose.connect(uri,{useUnifiedTopology:true}).then(()=>{
  app.listen(port,()=>{
    console.log(`server running on port ${port} and db connection successfuly`)
  })
})

