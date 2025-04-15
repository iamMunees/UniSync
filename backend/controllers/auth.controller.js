import User from "../models/user.model.js"
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { sendWelcomeEmail } from "../emails/emailHandlers.js";

// Signup function to handle user registration
export const signup = async (req, res) => {
	try {
		// Destructure necessary fields from request body
		const { name, username, email, password } = req.body;

		// Validate that all fields are provided
		if (!name || !username || !email || !password) {
			return res.status(400).json({ message: "All fields are required" });
		}

		// Check if the email already exists in the database
		const existingEmail = await User.findOne({ email });
		if (existingEmail) {
			return res.status(400).json({ message: "Email already exists" });
		}

		// Check if the username already exists in the database
		const existingUsername = await User.findOne({ username });
		if (existingUsername) {
			return res.status(400).json({ message: "Username already exists" });
		}

		// Validate password length
		if (password.length < 6) {
			return res.status(400).json({ message: "Password must be at least 6 characters" });
		}

		// Hash the password using bcrypt
		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(password, salt);

		// Create a new user instance with the provided details
		const user = new User({
			name,
			email,
			password: hashedPassword,
			username,
		});

		// Save the new user to the database
		await user.save();

		// Generate a JWT token for the user
		const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "3d" });

		// Set the JWT token in the cookie with the correct cookie name
		res.cookie("jwt-UniSync", token, {
			httpOnly: true, // Prevent XSS attacks by making the cookie accessible only to the server
			maxAge: 3 * 24 * 60 * 60 * 1000, // Cookie expires in 3 days
			sameSite: "strict", // Prevent CSRF attacks
			secure: process.env.NODE_ENV === "production", // Ensure cookie is sent over HTTPS in production
		});

		// Respond with a success message
		res.status(201).json({ message: "User registered successfully" });

		// Send a welcome email (optional, added try/catch for error handling)
		const profileUrl = process.env.CLIENT_URL + "/profile/" + user.username;
		try {
			await sendWelcomeEmail(user.email, user.name, profileUrl);
		} catch (emailError) {
			console.error("Error sending welcome email", emailError);
		}
	} catch (error) {
		// Catch any errors during the signup process and log them
		console.log("Error in signup: ", error.message);
		res.status(500).json({ message: "Internal server error" });
	}
};

// Login function to handle user authentication
export const login = async (req, res) => {
	try {
		// Destructure username and password from request body
		const { username, password } = req.body;

		// Check if the user exists in the database
		const user = await User.findOne({ username });
		if (!user) {
			return res.status(400).json({ message: "Invalid credentials" });
		}

		// Compare the provided password with the hashed password in the database
		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch) {
			return res.status(400).json({ message: "Invalid credentials" });
		}

		// Generate a JWT token for the logged-in user
		const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "3d" });

		// Set the JWT token in the cookie with the correct cookie name
		await res.cookie("jwt-UniSync", token, {
			httpOnly: true, // Prevent XSS attacks by making the cookie accessible only to the server
			maxAge: 3 * 24 * 60 * 60 * 1000, // Cookie expires in 3 days
			sameSite: "strict", // Prevent CSRF attacks
			secure: process.env.NODE_ENV === "production", // Ensure cookie is sent over HTTPS in production
		});

		// Respond with a success message
		res.json({ message: "Logged in successfully" });
	} catch (error) {
		// Catch any errors during the login process and log them
		console.error("Error in login controller:", error);
		res.status(500).json({ message: "Server error" });
	}
};



export const logout = (req,res)=>{
    res.clearCookie("jwt-UniSync")
    res.json({ message: "Logged out successfully"});
};

export const getCurrentUser = async (req, res) => {
	try {
		res.json(req.user);
	} catch (error) {
		console.error("Error in getCurrentUser controller:", error);
		res.status(500).json({ message: "Server error" });
	}
};
