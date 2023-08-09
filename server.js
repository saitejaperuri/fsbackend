import  express  from "express";
import mysql from "mysql"
import cors from "cors"
import jwt from "jsonwebtoken";
import bcryt from "bcrypt";
import cookieParser from "cookie-parser";


const app = express();
app.use(express.json)
app.use(cors({
    origin:["http://localhost:3003"],
    methods:["POST","GET"],
    credintials:true
}))
app.use(cookieParser());

const db = mysql.createConnection({
    host:"localhost",
    user: "root",
    password:"",
    database:"userData"
})

app.post("./register",(req,res)=> {
    const sql = "INSERT INTO login ('name','email', 'password') VALUES (?)";
    bcryt.hash(req.body.password.toString(), 8, (err, hash)=> {
        if (err) return res.json({Error:"Error"})
    })
    const values = [
        req.body.name,
        req.body.email,
        req.body.password

    ]
    db.query(sql, values, (err,res)=> {
        if (err) return res.json({Error:"Inserting Data Error"});
        return res.json({Status:"success"})
    })
})

const verify = (req,res) => {
    const token = req.cookies.token;
    if(!token){
        return res.json({Error:"Not Authenticated"});
    } else{
        jwt.verify(token,"token",(err,res)=>{
            if (err) {
                return res.json({Error:"token not valid"});
            }
            else{
                req.name = res.name;
            }
        })
    }
}

app.get("/",verify,(req,res) => {
    return res.json({Status:"success", name:req.name })
});

app.post("/login",(req,res) => {
    const sql = 'SELECT * FROM login WHERE email = ?';
    db.query(sql,[req.body.email], (err,data) => {
        if (err) return res.json({Error:"Login Error"});
        if (data.length > 0)  {
            bcrypt.compare(req.body.password.toString(), data[0].password ,(err,res) => {
                if (err) return res.json({Error:"Password Error"});
                if (res) {
                    const name = data[0].name;
                    const token = jwt.sign({name}, 'token', {expires: 30})
                    res.cookie("token",token);
                    return req.json({Status:"success"})
                }
                
            })
        }else {
            return res.json({Error:"No email existed"});
        }
    })
})


app.listen(4003,()=> {
    console.log("Server Running")
})