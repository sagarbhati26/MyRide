import mongoose,{Schema} from 'mongose';
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
const userSchema = new Schema({
    fullname:{
        firstName:{
            type:String,
        required:true,
        minLength:[3,'First name should be atleast 3 characters long']
        },
        lastName:{
            type:String,
            required:true,
            minLength:[3,'Last name should be atleast 3 characters long']
        }
    },
    email:{
        type:String,
        required:true,
        minLength:[7,'email should be of 7 characters']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        select:false
    },
    socketId:{
        type:String
    }
})

userSchema.pre("save",async function (next) {
    if(!this.isModified("password")) return next()
        this.password=bcrypt.hash(this.password, 10)
    next()
   
        
})
userSchema.methods.isPasswordCorrect= async function(password) {
    return await bcrypt.compare(password,this.password)    
    }
 userSchema.methods.generateAccessToken=function(){
    return jwt.sign({
        _id:this._id,
        email:this.email,
        fullname:this.fullname
    },
process.env.ACCESS_TOKEN_SECRET,{
    expiresIn:process.env.ACCESS_TOKEN_EXPIRY
})
 }

export const User = mongoose.model("User",userSchema)    