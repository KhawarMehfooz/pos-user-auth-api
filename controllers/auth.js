const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const registerUser = async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        const user = new User({
            fullName: req.body.fullName,
            email: req.body.email,
            password: hashedPassword
        });

        await user.save();

        return res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        return res.status(400).json({ message: error.message });
    }
};

const loginUser = async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });

        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);

        // Save token to user document
        user.token = token;
        await user.save();

        return res.json({ token });
    } catch (error) {
       return res.status(400).json({ message: error.message });
    }
};

const validateToken = async (req, res) => {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Bearer token is required' });
      }
  
      const token = authHeader.split(' ')[1];
  
      const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decodedToken.userId);
      if (!user) {
        return res.status(403).json({ message: 'Invalid token' });
      }
  
      return res.json({ message: "Valid Token" });
    } catch (error) {
      console.error('Error validating token:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }



module.exports = {
    registerUser,
    loginUser,
    validateToken
}