const bcrypt = require("bcrypt");
const pool = require("../utils/db");
const { createUser, getUserByEmail } = require("../models/userModel");
const { hashPassword, comparePassword } = require("../utils/hash");

// Handler untuk registrasi
const register = async (request, h) => {
  const { username, email, password } = request.payload;

  try {
    const existingUser = await getUserByEmail(email);
    if (existingUser) {
      return h.response({ message: "Email sudah terdaftar" }).code(400);
    }
    const hashedPassword = await hashPassword(password);
    await createUser(username, email, hashedPassword);
    return h.response({ message: "Registrasi berhasil" }).code(201);
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

    return h.response({ message: "Login berhasil" }).code(200);
  } catch (error) {
    console.error(error);
    return h.response({ message: "Terjadi kesalahan" }).code(500);
  }
};

// Handler untuk logout
const logout = async (request, h) => {
  request.cookieAuth.clear();
  return h.response({ message: "Logout berhasil" }).code(200);
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

module.exports = {
  register,
  login,
  logout,
  editProfile,
};
