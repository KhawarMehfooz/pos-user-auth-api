const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const registerUser = async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

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

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);

    const cookieExpiration = new Date();
    cookieExpiration.setMonth(cookieExpiration.getMonth() + 1)

    res.cookie('auth_token', token, {
      httpOnly: true,
      sameSite: 'strict',
      expires: cookieExpiration
    })

    user.token = token;
    await user.save();

    return res.status(200).json({ message: 'Login Successful', token, expires: cookieExpiration });
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

    return res.status(200).json({ 
      name: user.fullName,
      email: user.email,
      token: user.token 
    });
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