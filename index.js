const express = require('express')
const app = express()
const jwt = require('jsonwebtoken');
const port = process.env.PORT || 3000;
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const bodyParser = require('body-parser');
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

//app.use(express.json())
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

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
      title: 'Visitor Management System Group 19',
      version: '1.0.0',
      description: 'Visitor Management System using Swagger and Node.js',
    },
    securityDefinitions: {
      JWT: {
        type: 'apiKey',
        name: 'Authorization',
        in: 'header',
      },
    },
  },
  apis: ['./index.js'], // Path to your route files
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */

/**
 * @swagger
 * tags:
 *   - name: Alone Login
 *     description: To analyze the identity of user
 *   - name: User
 *     description: API operations related to user management
 *   - name: Visitor
 *     description: API operations related to visitor management
 *   - name: Visitor Log
 *     description: API operations related to visitor log management
 */

/**
 * @swagger
 * /login:
 *   post:
 *     tags:
 *      - Alone Login
 *     summary: Perform user login
 *     description: Endpoint for user authentication
 *     requestBody:
 *      description: User login information
 *      required: true
 *      content:
 *        application/json:
 *         schema:
 *          type: object
 *          properties:
 *            user_id:
 *              type: string
 *            password:
 *              type: string
 *     responses:
 *       200:
 *         description: OK
 *       401:
 *         description: Unauthorized
 */

//login POST request
app.post('/login', async (req, res) => {
    let data = req.body
    console.log(req.body)
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

/**
 * @swagger
 * /finduser:
 *   get:
 *     tags:
 *      - User
 *     summary: Find user information
 *     description: Retrieve user information based on the provided criteria.
 *     security:
 *       - BearerAuth: []  # Use the security scheme defined in your Swagger definition for authentication
 *     parameters:
 *       - in: query
 *         name: user_id
 *         schema:
 *           type: string
 *         description: The user_id of the user to find.
 *     responses:
 *       200:
 *         description: Successful response. User information retrieved.
 *         content:
 *           application/json:
 *             example:
 *               user_id: "example_user"
 *               name: "John Doe"
 *               email: "john@example.com"
 *       401:
 *         description: Unauthorized. Token not valid.
 *       403:
 *         description: Forbidden. User does not have access to finding users.
 *       404:
 *         description: User not found. The specified user_id does not exist.
 *       500:
 *         description: Internal Server Error. Something went wrong on the server.
 */

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

/**
 * @swagger
 * /registeruser:
 *   post:
 *     tags:
 *      - User
 *     summary: Register a new user
 *     description: Register a new user with the provided information.
 *     security:
 *       - BearerAuth: []  # Use the security scheme defined in your Swagger definition for authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           example:
 *             user_id: "new_user"
 *             password: "password123"
 *             name: "John Doe"
 *             unit: "Apartment A"
 *             hp_num: "+123456789"
 *             role: "admin"
 *     responses:
 *       200:
 *         description: Successful response. User registered successfully.
 *         content:
 *           application/json:
 *             example:
 *               message: "Registration request processed, new user is John Doe"
 *       400:
 *         description: Bad Request. User already exists.
 *       401:
 *         description: Unauthorized. Token not valid.
 *       403:
 *         description: Forbidden. User does not have access to registering users.
 *       500:
 *         description: Internal Server Error. Something went wrong on the server.
 */

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

/**
 * @swagger
 * /updateuser:
 *   patch:
 *     tags:
 *      - User
 *     summary: Update user information
 *     description: Update user information based on the provided data.
 *     security:
 *       - BearerAuth: []  # Use the security scheme defined in your Swagger definition for authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           example:
 *             user_id: "existing_user"
 *             password: "new_password"
 *             name: "Updated Name"
 *             unit: "Updated Unit"
 *             hp_num: "+987654321"
 *             role: "admin"
 *     responses:
 *       200:
 *         description: Successful response. User information updated successfully.
 *         content:
 *           application/json:
 *             example:
 *               message: "User updated! Updated Name"
 *       400:
 *         description: Bad Request. User does not exist.
 *       401:
 *         description: Unauthorized. Token not valid.
 *       403:
 *         description: Forbidden. User does not have access to update user information.
 *       500:
 *         description: Internal Server Error. Something went wrong on the server.
 */

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

/**
 * @swagger
 * /deleteuser:
 *   delete:
 *     tags:
 *      - User
 *     summary: Delete a user
 *     description: Delete a user based on the provided user_id.
 *     security:
 *       - BearerAuth: []  # Use the security scheme defined in your Swagger definition for authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           example:
 *             user_id: "user_to_delete"
 *     responses:
 *       200:
 *         description: Successful response. User deleted successfully.
 *         content:
 *           application/json:
 *             example:
 *               message: "User deleted user_to_delete"
 *       400:
 *         description: Bad Request. Cannot find the user to delete.
 *       401:
 *         description: Unauthorized. Token not valid.
 *       403:
 *         description: Forbidden. User does not have access to delete users.
 *       500:
 *         description: Internal Server Error. Something went wrong on the server.
 */

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

/**
 * @swagger
 * /registervisitor:
 *   post:
 *     tags:
 *      - Visitor
 *     summary: Register a new visitor
 *     description: Register a new visitor based on the provided data.
 *     security:
 *       - BearerAuth: []  # Use the security scheme defined in your Swagger definition for authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           example:
 *             ref: "visitor_reference_number"
 *             name: "Visitor Name"
 *             IC_num: "IC123456"
 *             car_num: "ABC123"
 *             hp_num: "+987654321"
 *             pass: true
 *             category: "Guest"
 *             date: "2023-12-31"
 *             unit: "A101"
 *     responses:
 *       200:
 *         description: Successful response. Visitor registered successfully.
 *         content:
 *           application/json:
 *             example:
 *               message: "Registration request processed, visitor is Visitor Name"
 *       400:
 *         description: Bad Request. Visitor with the provided reference number already exists.
 *       401:
 *         description: Unauthorized. Token not valid.
 *       500:
 *         description: Internal Server Error. Something went wrong on the server.
 */

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

/**
 * @swagger
 * /findvisitor:
 *   get:
 *     tags:
 *      - Visitor
 *     summary: Find visitors based on criteria
 *     description: Retrieve a list of visitors based on the provided criteria. Only residents can find their own visitors.
 *     security:
 *       - BearerAuth: []  # Use the security scheme defined in your Swagger definition for authentication
 *     parameters:
 *       - in: query
 *         name: ref
 *         description: Reference number of the visitor
 *         schema:
 *           type: string
 *       - in: query
 *         name: name
 *         description: Name of the visitor
 *         schema:
 *           type: string
 *       - in: query
 *         name: IC_num
 *         description: IC number of the visitor
 *         schema:
 *           type: string
 *       - in: query
 *         name: car_num
 *         description: Car number of the visitor
 *         schema:
 *           type: string
 *       - in: query
 *         name: hp_num
 *         description: Phone number of the visitor
 *         schema:
 *           type: string
 *       - in: query
 *         name: pass
 *         description: Whether the visitor has a pass (true/false)
 *         schema:
 *           type: boolean
 *       - in: query
 *         name: category
 *         description: Category of the visitor (e.g., Guest, Contractor)
 *         schema:
 *           type: string
 *       - in: query
 *         name: date
 *         description: Visit date of the visitor 
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: unit
 *         description: Unit of the visitor
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Successful response. List of visitors matching the criteria.
 *         content:
 *           application/json:
 *             example:
 *               - ref_num: "visitor_reference_number"
 *                 name: "Visitor Name"
 *                 IC_num: "IC123456"
 *                 car_num: "ABC123"
 *                 hp_num: "+987654321"
 *                 pass: true
 *                 category: "Guest"
 *                 visit_date: "2023-12-31"
 *                 unit: "A101"
 *               - ref_num: "another_reference_number"
 *                 name: "Another Visitor"
 *                 IC_num: "IC789012"
 *                 car_num: "XYZ789"
 *                 hp_num: "+123456789"
 *                 pass: false
 *                 category: "Contractor"
 *                 visit_date: "2023-12-30"
 *                 unit: "B202"
 *       401:
 *         description: Unauthorized. Token not valid.
 *       500:
 *         description: Internal Server Error. Something went wrong on the server.
 */

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

/**
 * @swagger
 * /updatevisitor:
 *   patch:
 *     tags:
 *      - Visitor
 *     summary: Update visitor information
 *     description: Update information of a visitor. Only residents and security can update their own visitors, while admin can update any visitor.
 *     security:
 *       - BearerAuth: []  # Use the security scheme defined in your Swagger definition for authentication
 *     parameters:
 *       - in: body
 *         name: Visitor Update Information
 *         description: JSON object containing the visitor information to be updated
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             ref_num:
 *               type: string
 *               description: Reference number of the visitor to be updated
 *               example: visitor_reference_number
 *             name:
 *               type: string
 *               description: Updated name of the visitor
 *               example: Updated Visitor Name
 *             IC_num:
 *               type: string
 *               description: Updated IC number of the visitor
 *               example: IC654321
 *             car_num:
 *               type: string
 *               description: Updated car number of the visitor
 *               example: XYZ789
 *             hp_num:
 *               type: string
 *               description: Updated phone number of the visitor
 *               example: +987654321
 *             pass:
 *               type: boolean
 *               description: Updated pass status of the visitor
 *               example: true
 *             category:
 *               type: string
 *               description: Updated category of the visitor (e.g., Guest, Contractor)
 *               example: Contractor
 *             visit_date:
 *               type: string
 *               format: date
 *               description: Updated visit date of the visitor 
 *               example: 2023-12-31
 *             unit:
 *               type: string
 *               description: Updated unit of the visitor
 *               example: B303
 *     responses:
 *       200:
 *         description: Successful response. Visitor information updated.
 *         content:
 *           application/json:
 *             example:
 *               ref_num: "visitor_reference_number"
 *               name: "Updated Visitor Name"
 *               IC_num: "IC654321"
 *               car_num: "XYZ789"
 *               hp_num: "+987654321"
 *               pass: true
 *               category: "Contractor"
 *               visit_date: "2023-12-31"
 *               unit: "B303"
 *       401:
 *         description: Unauthorized. Token not valid.
 *       500:
 *         description: Internal Server Error. Something went wrong on the server.
 */

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

/**
 * @swagger
 * /deletevisitor:
 *   delete:
 *     tags:
 *       - Visitor
 *     summary: Delete a visitor
 *     description: Delete a visitor based on the reference number. Only residents and security can delete their own visitors, while admin can delete any visitor.
 *     security:
 *       - BearerAuth: []  # Use the security scheme defined in your Swagger definition for authentication
 *     parameters:
 *       - in: body
 *         name: Visitor Deletion Information
 *         description: JSON object containing the reference number of the visitor to be deleted
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             ref_num:
 *               type: string
 *               description: Reference number of the visitor to be deleted
 *               example: visitor_reference_number
 *     responses:
 *       200:
 *         description: Successful response. Visitor deleted.
 *         content:
 *           application/json:
 *             example:
 *               message: "The visitor under reference number of visitor_reference_number has been deleted :D!"
 *       401:
 *         description: Unauthorized. Token not valid.
 *       500:
 *         description: Internal Server Error. Something went wrong on the server.
 */

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

/**
 * @swagger
 * /createQRvisitor:
 *   get:
 *     tags:
 *       - Visitor
 *     summary: Create QR code for visitor
 *     description: |
 *       Create a QR code for a visitor based on their IC number.
 *       The QR code contains visitor information such as reference number, name, category, and contact number.
 *     parameters:
 *       - in: body
 *         name: Visitor Information
 *         description: Visitor information for creating QR code
 *         schema:
 *           type: object
 *           properties:
 *             IC_num:
 *               type: string
 *               description: IC number of the visitor
 *     responses:
 *       200:
 *         description: QR code created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                 qrCodeUrl:
 *                   type: string
 *                   format: uri
 *                   description: URL to the generated QR code
 *       400:
 *         description: Invalid request or visitor not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *     security:
 *       - bearerAuth: []
 */

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

/**
 * @swagger
 * /checkIn:
 *   post:
 *     tags:
 *       - Visitor Log
 *     summary: Create a visitor log
 *     description: |
 *       Create a visitor log for check-in. Only security and admin roles are allowed to create logs.
 *     requestBody:
 *       description: Visitor log information for check-in
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               log_id:
 *                 type: string
 *                 description: Unique log ID
 *               ref:
 *                 type: string
 *                 description: Reference number of the visitor
 *     responses:
 *       200:
 *         description: Visitor log created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                 logData:
 *                   type: object
 *                   description: Created visitor log data
 *       400:
 *         description: Invalid request or duplicate log ID
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *     security:
 *       - bearerAuth: []
 */

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

/**
 * @swagger
 * /findvisitorlog:
 *   get:
 *     tags:
 *       - Visitor Log
 *     summary: Find visitor logs
 *     description: |
 *       Find visitor logs based on specified criteria. Only security and admin roles are allowed to find logs.
 *     parameters:
 *       - in: query
 *         name: log_id
 *         schema:
 *           type: string
 *         description: Optional. Log ID to filter logs.
 *       - in: query
 *         name: ref_num
 *         schema:
 *           type: string
 *         description: Optional. Reference number of the visitor to filter logs.
 *     responses:
 *       200:
 *         description: Visitor logs found successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   log_id:
 *                     type: string
 *                     description: Unique log ID
 *                   ref_num:
 *                     type: string
 *                     description: Reference number of the visitor
 *                   CheckIn_Time:
 *                     type: string
 *                     format: date-time
 *                     description: Check-in time
 *                   CheckOut_Time:
 *                     type: string
 *                     format: date-time
 *                     description: Check-out time
 *                   user_id:
 *                     type: string
 *                     description: User ID associated with the log
 *       400:
 *         description: Invalid request or insufficient permissions
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *     security:
 *       - bearerAuth: []
 */

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

/**
 * @swagger
 * /checkOut:
 *   patch:
 *     tags:
 *       - Visitor Log
 *     summary: Update a visitor log to checkout visitor
 *     description: |
 *       Update the specified visitor log to mark the visitor as checked out. Only security and admin roles are allowed to update logs.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               log_id:
 *                 type: string
 *                 description: Log ID of the visitor log to update
 *             required:
 *               - log_id
 *     responses:
 *       200:
 *         description: Visitor log updated successfully
 *       400:
 *         description: Invalid request or insufficient permissions
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *     security:
 *       - bearerAuth: []
 */

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
  console.log(data.user_id)
  console.log(verify)
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