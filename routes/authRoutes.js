const authController = require("../controllers/authController");

const authRoutes = [
  {
    method: "POST",
    path: "/register",
    handler: authController.register,
    options: {
      auth: false, // Nonaktifkan autentikasi untuk endpoint ini
    },
  },
  {
    method: "POST",
    path: "/login",
    handler: authController.login,
    options: {
      auth: false, // Nonaktifkan autentikasi untuk endpoint ini
    },
  },
  {
    method: "POST",
    path: "/users/logout",
    handler: authController.logout,
    options: {
      auth: "session", // Hanya user yang login dapat mengakses
    },
  },
  {
    method: "PUT",
    path: "/users/profile",
    handler: authController.editProfile,
    options: {
      auth: "session",
    },
  },
];

module.exports = authRoutes;
