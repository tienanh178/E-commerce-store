import jwt from "jsonwebtoken";

const adminAuth = async (req, res, next) => {
  try {
    const { token } = req.headers;
    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Not Authorized, please login again",
      });
    }
    const token_decode = jwt.verify(token, process.env.JWT_SECRET);

    if (token_decode !== process.env.ADMIN_EMAIL + process.env.ADMIN_PASSWORD) {
      res.json({ success: false, message: "Not authorized, login again" });
    }
    next();
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: error.message });
  }
};

export default adminAuth;
