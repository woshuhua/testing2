const express = require('express')
const app = express()
const jwt = require('jsonwebtoken');
const port = process.env.PORT || 3000;
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const bcrypt = require('bcrypt');
const saltRounds = 10;
const qrCode_c = require('qrcode');
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

// Swagger setup
const swaggerOptions = {
  definition: {
    openapi: '3.0.0', // Specify the OpenAPI version
    info: {
      title: 'Your API',
      version: '1.0.0',
      description: 'API documentation using Swagger',
    },
  },
  apis: ['./index.js'], // Path to your route files
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Perform user login
 *     description: Endpoint for user authentication
 *     parameters:
 *       - in: body
 *         name: User Login Information
 *         description: Username and Password
 *         schema:
 *           type: object
 *           properties:
 *             user_id:
 *               type: string
 *             password:
 *               type: string
 *     responses:
 *       200:
 *         description: OK
 *       401:
 *         description: Unauthorized
 */

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

//find user GET request
app.get('/finduser', verifyToken, async (req, res)=>{
  let authorize = req.user.role //reading the token for authorisation
  let data = req.body //requesting the data from body
  //checking the role of user
  if (authorize == "resident"|| authorize == "security"){
    res.send(errorMessage() + "\nyou do not have access to finding users!")
  }else if (authorize == "admin"){
    const newUser = await findUser(data) //calling the function to find user
    if (newUser){ //checking if user exist
      res.send(newUser)
    }else{
      res.send(errorMessage() + "User does not exist sadly :[")
    }
  //token does not exist
  }else {
      res.send(errorMessage() + "Token not valid!")
    }
  })

//register user post request
app.post('/registeruser', verifyToken, async (req, res)=>{
  let authorize = req.user.role //reading the token for authorisation
  let data = req.body //requesting the data from body
  //checking the role of user
  if (authorize == "security" || authorize == "resident"){
    res.send("you do not have access to registering users!")
  }else if (authorize == "admin" ){
    const newUser = await registerUser(data)
    if (newUser){ //checking is registration is succesful
      res.send("Registration request processed, new user is " + newUser.name)
    }else{
      res.send(errorMessage() + "User already exists!")
    }
  //token does not exist
  }else {
      res.send(errorMessage() + "Token not valid!")
    }
  })

//update user PATCH request
app.patch('/updateuser', verifyToken, async (req, res)=>{
  let authorize = req.user.role //reading the token for authorisation
  let data = req.body //requesting the data from body
  //checking the role of user
  if (authorize == "security" || authorize == "resident"){
    res.send("you do not have access to update user information!")
  }else if (authorize == "admin" ){
    const result = await updateUser(data)
    if (result){ // checking if the user exist and updated
      res.send("User updated! " + result.value.name)
    }else{
      res.send(errorMessage() + "User does not exist!")
    }
  }else {
      res.send(errorMessage() + "Token is not found!")
    }
})

//delete user DELETE request
app.delete('/deleteuser', verifyToken, async (req, res)=>{
  let data = req.body
  let authorize = req.user.role
  //checking the role of user
  if (authorize == "security" || authorize == "resident"){
    res.send("you do not have access to registering users!")
  }else if (authorize == "admin" ){
    const result = await deleteUser(data)
    //checking if item is deleted
    if (result.deletedCount == "1"){
      res.send("user deleted " + data.user_id)
    }else{
      res.send(errorMessage() + "Cannot find the user to delete!")
    }
  }else {
      res.send(errorMessage() + "Token not valid!")
    }
  }
)

//register visitor POST request
app.post('/registervisitor', verifyToken, async (req, res)=>{
  let authorize = req.user.role
  let loginUser = req.user.user_id
  let data = req.body
  //checking if token is valid
  if(authorize){
  const visitorData = await registerVisitor(data, loginUser) //register visitor
    if (visitorData){
      res.send("Registration request processed, visitor is " + visitorData.name)
    }else{
      res.send(errorMessage() + "Visitor already exists! Add a visit log instead!")
    }
  }else {
      res.send(errorMessage() + "Not a valid token!")
    }
  }
)

//find visitor GET request
app.get('/findvisitor', verifyToken, async (req, res)=>{
  let authorize = req.user//reading the token for authorisation
  let data = req.body //requesting the data from body
  //checking the role of user
  if (authorize.role){
    const result = await findVisitor(data,authorize) //find visitor
    res.send(result)
  }else{
    res.send(errorMessage() + "Not a valid token!") 
  }
  })

//update visitor PATCH request
app.patch('/updatevisitor', verifyToken, async (req, res)=>{
  let authorize = req.user
  let data = req.body
  //checking if token is valid
  if(authorize.role){
    const result = await updateVisitor(data,authorize) // update visitor
    if (result){
      res.send("Visitor " + result.value.user_id + " has been updated :D!")
    }else{
      res.send(errorMessage() + "Visitor does not exist!")
    }
  }else {
      res.send(errorMessage() + "Not a valid token!")
    }
})

//delete visitor DELETE request
app.delete('/deletevisitor', verifyToken, async (req, res)=>{
  let data = req.body
  let authorize = req.user
  //checking if token is valid
  if(authorize.role){
  const deletedV = await deleteVisitor(data,authorize) //delete visitor
    if (deletedV.deletedCount == "1"){ //check for successful delete
      res.send("The visitor under reference number of " + data.ref_num + " has been deleted :D!")
    }else{
      res.send(errorMessage() + "No such visitor found D: , perhaps you actually wished your ex visited?")
    }
  }else {
      res.send(errorMessage() + "Not a valid token!")
    }
  }
)

//create a qr code for visitor
app.get('/createQRvisitor', verifyToken, async (req, res)=>{
  let data = req.body
  let authorize = req.user
  if (authorize.role){ //checking if token is valid
  const uri = await qrCreate(data) //create qr code
    if (uri){
      res.write("QR code created for visitor! Paste the link below into a browser :D\n")
      res.end(uri)
    }else{
      res.send(errorMessage() + "No such visitor found")
    }
  }else {
      res.send(errorMessage() + "Not a valid token!")
    }
  }
)

//create a visitor log
app.post('/checkIn', verifyToken, async (req, res,err)=>{
  let data = req.body
  let authorize = req.user.role
  //checking role of users
  if (authorize == "security" || authorize == "admin")
  { //roles that can create visitor logs
    const logData = await createLog(data,req.user) //create logs
    if (logData){
      res.send({message : "Visitor Log Created!", logData})
    }else{
      res.send(errorMessage() + "Duplicate Log! Might wanna find the admin")
    }
  }else if (authorize == "resident" ){
    res.send(errorMessage() + "You do not have access to create visitor logs!")
  }else{
    res.send(errorMessage() + "token not valid D:")
    }
  })

//find visitor log
app.get('/findvisitorlog', verifyToken, async (req, res)=>{
    let authorize = req.user.role //reading the token for authorisation
    let data = req.body //requesting the data from body
    //checking the role of user
    if (authorize == "resident"){
      res.send(errorMessage() + "you do not have access to registering users!")
    }
    else if (authorize == "security" || authorize == "admin"){
      const result = await findLog(data) //find logs
      res.send(result)
    }
  }
  )

//update a visitor log to checkout visitor
app.patch('/checkOut', verifyToken, async (req, res)=>{
  let data = req.body
  let authorize = req.user.role
  if (authorize == "security" || authorize == "admin"){ //check roles that can update visitor logs
    const logData = await updateLog(data)
    if (typeof logData == "object"){ //if returned data is object, means log is updated
      res.send( "Visitor succesfully checkout")
    }else{
      res.send(errorMessage() + "Could not find log :[")
    }
  }else if (authorize == "resident" ){
    res.send("You do not have access to update visitor logs!")
  }else{
    res.send(errorMessage() + "Please enter a valid role!")
    }
  })


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

async function findUser(newdata) {
  //verify if there is duplicate username in databse
  const match = await user.find({user_id : newdata.user_id},{projection: {password: 0, _id : 0}}).next()
  return (match)
}

async function registerUser(newdata) {
  //verify if there is duplicate username in databse
  const match = await user.find({user_id : newdata.user_id}).next()
    if (match) {
      return 
    } else {
      //encrypt password by hashing
      const hashed = await encryption(newdata.password)
      // add info into database
      await user.insertOne({
        "user_id": newdata.user_id,
        "password": hashed,
        "name": newdata.name,
        "unit": newdata.unit,
        "hp_num" : newdata.hp_num,
        "role" : newdata.role
      })
  const newUser=await user.find({user_id : newdata.user_id}).next()
  console.log(newUser)
  return (newUser)
}}
    
async function updateUser(data) {
  if (data.password){
  data.password = await encryption(data.password) //encrypt the password
  }
  result = await user.findOneAndUpdate({user_id : data.user_id},{$set : data}, {new: true})
  if(result.value == null){ //check if user exist
    return 
  }else{
    return (result)
  }
}

async function deleteUser(data) {
  //delete user from database
  success = await user.deleteOne({user_id : data.user_id})
  return (success) // return success message
}

async function registerVisitor(newdata, currentUser) {
  //verify if there is duplciate ref_num
  const match = await visitor.find({"ref_num": newdata.ref}).next()
    if (match) {
      return 
    } else {
      // add info into database
      await visitor.insertOne({
        "ref_num" : newdata.ref,
        "name": newdata.name,
        "IC_num": newdata.IC_num,
        "car_num": newdata.car_num,
        "hp" : newdata.hp_num,
        "pass": newdata.pass,
        "category" : newdata.category,
        "visit_date" : newdata.date,
        "unit" : newdata.unit,
        "user_id" : currentUser
      })
          return (newdata)
    }  
}

async function findVisitor(newdata, currentUser){
  if (currentUser.role == "resident"){
    filter=Object.assign(newdata, {"user_id" : currentUser.user_id}) // only allow resident to find their own visitors
    match = await visitor.find(filter, {projection: {_id :0}}).toArray()
  }else if (currentUser.role == "security" || currentUser.role == "admin"){ // allow security and admin to find all visitors
    match = await visitor.find(newdata).toArray()
  }
  if (match.length != 0){ //check if there is any visitor
    return (match)
  } else{
    return (errorMessage() + "Visitor does not exist!")
  }
}

async function updateVisitor(data, currentUser) {
  if (currentUser.role == "resident"|| currentUser.role == "security"){ //only allow resident and security to update their own visitors
    result = await visitor.findOneAndUpdate({"ref_num": data.ref_num, "user_id" : currentUser.user_id },{$set : data}, {new:true})
  }else if (currentUser.role == "admin"){
    result = await visitor.findOneAndUpdate({"ref_num": data.ref_num},{$set : data}, {new:true}) //allow admin to update all visitors
  }
  if(result.value == null){ //check if visitor exist
    return 
  }else{
    return (result)
  }
}

async function deleteVisitor(newdata, currentUser) {
  if (currentUser.role == "resident"|| currentUser.role == "security"){ //only allow resident and security to delete their own visitors
    success  = await visitor.deleteOne({ref_num : newdata.ref_num, user_id : currentUser.user_id})
  }else if (currentUser.role == "admin"){ //allow admin to delete all visitors
    success  = await visitor.deleteOne({ref_num : newdata.ref_num})
  }
  return (success) // return success message
}

async function createLog(newdata,currentUser) {
  //verify if there is duplicate log id
  const match = await visitorLog.find({"log_id": newdata.log_id}).next()
    if (match) {
      return 
    } else {
      // add info into database
      let dateTime = currentTime()
      await visitorLog.insertOne({
        "log_id": newdata.log_id,
        "ref_num" : newdata.ref,
        "CheckIn_Time": dateTime,
        "CheckOut_Time": "",
        "user_id" : currentUser.user_id
      })
  const log = visitorLog.find({"log_id": newdata.log_id}, {projection :{_id : 0 }}).next()
    return (log)
    }  
}

async function updateLog(newdata) {
  //verify if username is already in databse
  let dateTime = currentTime()
  const newLog = await visitorLog.findOneAndUpdate({"log_id": newdata.log_id},{$set : {CheckOut_Time: dateTime}}) //update the checkout time
    if (newLog.value == null) { //check if log exist
      return 
    } else {
        return (newLog)
    }  
}

//function to create qrcode file
async function qrCreate(data){
  visitorData = await visitor.find({"IC_num" : data.IC_num}, {projection : {"ref_num" : 1 , "name" : 1 , "category" : 1 , "hp" : 1, "_id" : 0}}).next() //find visitor data
  if(visitorData){ //check if visitor exist
    let stringdata = JSON.stringify(visitorData)
    const base64 = await qrCode_c.toDataURL(stringdata) //convert to qr code to data url
    return (base64)
  }else{
    return
  }
}

//find visitor logs
async function findLog(newdata){
  const match = await visitorLog.find(newdata, {projection: {"_id":0}}).toArray() //find logs
  if (match.length != 0){   //check if there is any log
    return (match) 
  } else{
    return (errorMessage() + "Visitor log does not exist !")
  }
}

// to get the current time 
function currentTime(){
  const today = new Date().toLocaleString("en-US", {timeZone: "singapore"}) 
  return today
}

//generate token for login authentication
function generateToken(loginProfile){
  return jwt.sign(loginProfile, 'UltimateSuperMegaTitanicBombasticGreatestBestPOGMadSuperiorTheOneandOnlySensationalSecretPassword', { expiresIn: '1h' });
}

//verify generated tokens
function verifyToken(req, res, next){
  let header = req.headers.authorization
  let token = header.split(' ')[1] //checking header
  jwt.verify(token,'UltimateSuperMegaTitanicBombasticGreatestBestPOGMadSuperiorTheOneandOnlySensationalSecretPassword',function(err,decoded){
    if(err) {
      res.send(errorMessage() + "Token is not valid D:, go to the counter to exchange (joke)")
      return
    }
    req.user = decoded // bar

    next()
  });
}

//bcrypt functions to generate a hashed password
async function encryption(data){
  const salt= await bcrypt.genSalt(saltRounds)
  const hashh = await bcrypt.hash(data,salt)
  return hashh
}

//error message generator
function errorMessage(){
  const x = Math.floor(Math.random()*6)
  if (x == 0){
    return ("Oopsie Daisy\n")
  }else if (x == 1){
    return ("Error! Error! Error!\n")
  }else if (x==2){
    return ("I can accept failure. Everyone fails at something. But I can't accept not trying. ― Michael Jordan\n")
  }else if (x==3){
    return ("Waoh how did you even get an error here?\n")
  }else if (x==4){
    return ("Something went wrong! FeelsBadMan\n")
  }else if (x==5){
    return ("Hi, I'm Error Man , I'm here to tell you\n")
  }else{
    return ("Oi bo- Sir/Madam, we seem to have an error\n")
  }
}