/*
Author: Jose Mondragon
Date: 11-15-26
Description: Express-Todo-List
*/
//packages
import express from 'express'
import{engine} from 'express-handlebars'
import sqlite3 from 'sqlite3'
import {open} from 'sqlite'
import bcrypt from 'bcrypt'
import cookieParser from 'cookie-parser'
import {v4 as uuidv4} from 'uuid'

//connect to the database
const dbPromise = open({
    filename: './database/todolist.sqlite',
    driver: sqlite3.Database
})

const app = express()
const saltRounds = 10
const port = 8080

//configuration
app.use(express.urlencoded())
app.use('/static',express.static('./static'))
app.use(cookieParser())



app.engine('handlebars', engine());
app.set('view engine','handlebars');

const authenticateMiddleware = async (req,res,next) =>{
    console.log(req.cookies)
    if(!req.cookies || !req.cookies.authToken){
        console.log("Opps?")
        return next()
    }

    const db = await dbPromise;
    try{
        console.log("trying")
        const token = await db.get("SELECT * FROM authtokens WHERE token=?", [req.cookies.authToken]);
        if(token){

            const user = await db.get("SELECT user_id, username FROM users WHERE user_id=?", [token.user_id]);
            req.user = user;
        }
        next()
    }
    catch(err){
        console.log("Bad token error");
        console.log(err);
        return next();
    }
}


app.use(authenticateMiddleware);

//homepage
app.get("/", async(req,res) => {
    if(!req.user){
        return res.redirect("/login")
    }
    const db = await dbPromise
    const tasks = await db.all(
        "SELECT * FROM tasks WHERE user_id = ?",
        [req.user.user_id]
    )
    res.render("home", {tasks:tasks})
})

app.get("/login", (req,res) => {
    res.render("login")
})

app.get("/register",(req,res) =>{
    res.render("register")
})


app.get("/logout",(req,res) =>{
    res.clearCookie("authToken");
    return res.redirect("/login");
})
//home page but for post
app.post("/",async(req,res)=>{
    const db = await dbPromise

    const task_desc = req.body.task_desc
    const user_id = req.user.user_id

    await db.run("INSERT INTO tasks (user_id,task_desc,is_complete) VALUES (?,?,?)",[user_id,task_desc,false])


    return res.redirect("/")
})

app.post("/register" , async (req,res) => {
    //gathers data in the request body
    const username = req.body.username
    const password = req.body.password
    const confirmPassword = req.body.confirmPassword;

    const db = await dbPromise
    //checks if all three have input, otherwise produce an error
    if(!username || !password || !confirmPassword){
        return res.render("register",{
            error: "All fields required"
        })
    }
    // checks if password is equal to confirm password
    if(password !== confirmPassword){
        return res.render("register",{
            error:"Passwords must match"
        })
    }

    const hashPass = await bcrypt.hash(password,saltRounds)



    let user = null;
    // creates token
    const authToken = uuidv4();
    try{
        await db.run("INSERT INTO users (username,password) VALUES (?,?);", [username, hashPass])
        user = await db.get("SELECT user_id FROM users WHERE username = ?", [username])
        await db.run("INSERT INTO authtokens (token,user_id) VALUES (?,?)", [authToken,user.user_id]);
        res.cookie("authToken",authToken);

    }
    catch(err){
        console.log(err)
        return res.render('register',{
            error: " Registration failed. Username may already exist."
        })

    }


    return res.redirect('/')
})


app.post("/login", async (req,res)=>{
    const db = await dbPromise

    const username = req.body.username
    const password = req.body.password

    try{

        if(!username || !password){
            return res.render("login",{
                error: "All field required"
            });
        }

        const user = await db.get("SELECT * FROM users WHERE username=?;",[username])

        if(!user){
            return res.render('login',{
                error:  "Error: username or password incorrect"
            });
        }
        const passwordmatch = await bcrypt.compare(password,user.password)
        if(!passwordmatch){
            return res.render("login",{
                error: "Error: isername or password incorrect"
            })
        }


        const token = uuidv4();

        await db.run("INSERT INTO authtokens(token,user_id) VALUES (?,?);",
           [token,user.user_id]
           );
    res.cookie("authToken",token);

    }
    catch (err){
        console.log(err)
        return res.render('login')
    }
    return res.redirect("/");
})


// creates a server and listens on port 8080
app.listen(port, () => {
    console.log(`Server started on port: ${port}`)
})


