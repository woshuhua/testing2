const express = require('express')
const app = express()
const jwt = require('jsonwebtoken');
const port = process.env.PORT || 3000;

const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = "mongodb+srv://xuhuan:xuhuan01234@cluster0.7krsk3h.mongodb.net/?retryWrites=true&w=majority";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true, 
    }
  });

//start of port
client.connect() 

//variables to define which collection used
const user = client.db("Visitor_Management_v1").collection("users")
const visitor = client.db("Visitor_Management_v1").collection("visitors")
const visitorLog = client.db("Visitor_Management_v1").collection("visitor_log")

app.use(express.json())

app.get('/', (req, res) => {
   res.send('Hello World!')
})

app.listen(port, () => {
   console.log(`Example app listening on port ${port}`)
})

//login GET request
app.post('/login', async (req, res) => {
    let data = req.body
    let result = await login(data);
    const loginuser = result.verify
    const token = result.token
    //check the returned result if its a object, only then can we welcome the user
    if (typeof loginuser == "object") { 
      res.write(loginuser.user_id + " has logged in!")
      res.write("\nWelcome "+ loginuser.name + "!")
      res.end("\nYour token : " + token)
    }else {
      //else send the failure message
      res.send(errorMessage() + result)
    }
  });

  async function login(data) {
    console.log("Alert! Alert! Someone is logging in!") //Display message to ensure function is called
    //Verify username is in the database
    let verify = await user.find({user_id : data.user_id}).next();
    if (verify){
      //verify password is correct
      const correctPassword = await bcrypt.compare(data.password,verify.password);
      if (correctPassword){
        token = generateToken(verify)
        return{verify,token};
      }else{
        return ("Wrong password D: Forgotten your password?")
      }
    }else{
      return ("No such user ID found D:")
  }}