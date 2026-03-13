import userModel from "../models/user.model.js";
import jwt from "jsonwebtoken";
import { sendEmail } from "../service/mail.service.js";


export async function register(req, res) {

    const { username, email, password } = req.body;

    const isUserAlreadyExists = await userModel.findOne({
        $or: [ { email }, { username } ]
    })

    if (isUserAlreadyExists) {
        return res.status(400).json({
            message: "User with this email or username already exists",
            success: false,
            err: "User already exists"
        })
    }

    const user = await userModel.create({ username, email, password })

    const EmailverificationToken = jwt.sign({
        email: user.email,
    }, process.env.JWT_SECRET)
await sendEmail({
  to: email,
  subject: "Verify your email - Perplexity",
  html: `
    <div style="font-family: Arial, sans-serif; line-height: 1.6;">
      <h2>Welcome to Perplexity 🚀</h2>
      
      <p>Hi ${username},</p>
      
      <p>Thanks for signing up. Please confirm your email address to activate your account.</p>
      
      <p>
        <a 
          href="http://localhost:3000/api/auth/verify-email?token=${EmailverificationToken}" 
          style="
            display:inline-block;
            padding:10px 18px;
            background-color:#4f46e5;
            color:#ffffff;
            text-decoration:none;
            border-radius:6px;
            font-weight:bold;
          "
        >
          Verify Email
        </a>
      </p>

      <p>If you didn’t create this account, you can safely ignore this email.</p>

      <p>Thanks,<br/>The Perplexity Team</p>
    </div>
  `
});

    res.status(201).json({
        message: "User registered successfully",
        success: true,
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        }
    });



}

export async function login(req, res) {
    const { email, password } = req.body;

    const user = await userModel.findOne({ email })

    if (!user) {
        return res.status(400).json({
            message: "Invalid email or password",
            success: false,
            err: "User not found"
        })
    }

    const isPasswordMatch = await user.comparePassword(password);

    if (!isPasswordMatch) {
        return res.status(400).json({
            message: "Invalid email or password",
            success: false,
            err: "Incorrect password"
        })
    }

    if (!user.verified) {
        return res.status(400).json({
            message: "Please verify your email before logging in",
            success: false,
            err: "Email not verified"
        })
    }

    const token = jwt.sign({
        id: user._id,
        username: user.username,
    }, process.env.JWT_SECRET, { expiresIn: '7d' })

    res.cookie("token", token)

    res.status(200).json({
        message: "Login successful",
        success: true,
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        }
    })

}

/**
 * @desc Get current logged in user's details
 * @route GET /api/auth/get-me
 * @access Private
 */
export async function getMe(req, res) {
    const userId = req.user.id;

    const user = await userModel.findById(userId).select("-password");

    if (!user) {
        return res.status(404).json({
            message: "User not found",
            success: false,
            err: "User not found"
        })
    }

    res.status(200).json({
        message: "User details fetched successfully",
        success: true,
        user
    })
}

export async function verifyEmail(req, res) {
    const { token } = req.query;
  
    try {


        const decoded = jwt.verify(token, process.env.JWT_SECRET);


        const user = await userModel.findOne({ email: decoded.email });

        if (!user) {
            return res.status(400).json({
                message: "Invalid token",
                success: false,
                err: "User not found"
            })
        }

        user.verified = true;
    await user.save();

   const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.6; text-align: center; padding: 40px;">
      <h2 style="color: #4f46e5;">Email Verified Successfully! 🎉</h2>
        <p style="font-size: 18px; color: #333;">Your email has been verified. You can now log in to your account.</p>
    </div>
  `;
      return res.send(html);
    } catch (err) {
        return res.status(400).json({
            message: "Invalid or expired token",
            success: false,
            err: err.message
        })
}

}