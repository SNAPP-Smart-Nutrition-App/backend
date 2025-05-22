const bcrypt = require("bcrypt");
const pool = require("../utils/db");
const { createUser, getUserByEmail } = require("../models/userModel");
const { hashPassword, comparePassword } = require("../utils/hash");
const jwt = require("jsonwebtoken");

// Handler untuk registrasi
const register = async (request, h) => {
  const { username, email, password } = request.payload;
  try {
    const existingUser = await getUserByEmail(email);
    if (existingUser) {
      return h.response({ message: "Email sudah terdaftar" }).code(400);
    }
    const hashedPassword = await hashPassword(password);
    const userId = await createUser(username, email, hashedPassword);

    // Buat token JWT
    const token = jwt.sign(
      {
        userId: userId,
        username: username,
        email: email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return h
      .response({
        status: "success",
        message: "Akun berhasil didaftarkan",
        token: token,
        user: {
          id: userId,
          name: username,
          email: email,
          profile_picture: "",
          proteinTarget: 0,
        },
      })
      .code(201);
  } catch (error) {
    console.error(error);
    return h.response({ message: "Terjadi kesalahan" }).code(500);
  }
};

// Handler untuk login
const login = async (request, h) => {
  const { email, password } = request.payload;
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return h.response({ message: "Email atau password salah" }).code(401);
    }

    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      return h.response({ message: "Email atau password salah" }).code(401);
    }

    // Simpan sesi pengguna
    request.cookieAuth.set({
      userId: user.id,
      username: user.username,
      email: user.email,
    });

    // Buat token JWT
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        email: user.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return h
      .response({
        status: "success",
        message: "Login berhasil",
        token: token,
        user: {
          id: user.id,
          name: user.username,
          email: user.email,
          profile_picture: "https://server.com/profile/" + user.username + ".jpg",
          proteinTarget: "0",
        },
      })
      .code(200);
  } catch (error) {
    console.error(error);
    return h.response({ message: "Terjadi kesalahan" }).code(500);
  }
};

// Handler untuk logout
const logout = async (request, h) => {
  request.cookieAuth.clear();
  return h
    .response({
      status: "success",
      message: "Logout berhasil",
    })
    .code(200);
};

// Handler untuk edit profile
const editProfile = async (request, h) => {
  const { username, password } = request.payload;
  const userId = request.auth.credentials.userId;

  try {
    // Validasi input
    if (!username || !password) {
      return h
        .response({
          message: "Username dan password harus diisi",
        })
        .code(400);
    }

    // Validasi username
    if (typeof username !== "string" || username.trim() === "") {
      return h
        .response({
          message: "Username tidak valid",
        })
        .code(400);
    }

    // Hash password baru
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update username dan password sekaligus
    await pool.query("UPDATE users SET username = ?, password = ? WHERE id = ?", [username, hashedPassword, userId]);

    // Update kredensial sesi dengan username baru
    request.cookieAuth.set({
      ...request.auth.credentials,
      username: username,
    });

    return h
      .response({
        message: "Profile berhasil diperbarui",
      })
      .code(200);
  } catch (error) {
    console.error("Error:", error);
    return h
      .response({
        message: "Terjadi kesalahan pada server",
      })
      .code(500);
  }
};

const verifyToken = async (request, h) => {
  const { token } = request.payload || request.query || {};

  if (!token) {
    return h.response({ valid: false, message: "Token tidak ditemukan" }).code(401);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return h.response({ valid: true, user: decoded }).code(200);
  } catch (error) {
    return h.response({ valid: false, message: "Token tidak valid" }).code(401);
  }
};

module.exports = {
  register,
  login,
  logout,
  editProfile,
  verifyToken,
};
