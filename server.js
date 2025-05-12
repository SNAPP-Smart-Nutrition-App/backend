const Hapi = require("@hapi/hapi");
require("dotenv").config();
const authRoutes = require("./routes/authRoutes");

const init = async () => {
  const server = Hapi.server({
    port: process.env.PORT || 8080,
    host: process.env.NODE_ENV !== "production" ? "localhost" : "0.0.0.0",
    routes: {
      cors: {
        origin: ["*"],
      },
    },
  });

  // Konfigurasi sesi menggunakan cookie
  server.state("session", {
    ttl: 24 * 60 * 60 * 1000, // Sesi berlaku selama 1 hari
    isSecure: process.env.NODE_ENV === "production", // Hanya secure pada produksi
    isHttpOnly: true, // Hanya dapat diakses oleh server
    path: "/", // Path untuk menyimpan cookie
    password: process.env.COOKIE_SECRET, // Password untuk cookie dari env
  });

  // Daftarkan plugin cookie
  await server.register(require("@hapi/cookie"));

  // Konfigurasi autentikasi dengan cookie
  server.auth.strategy("session", "cookie", {
    cookie: {
      name: "sid",
      password: process.env.COOKIE_SECRET, // Rahasia untuk mengenkripsi cookie
      isSecure: process.env.NODE_ENV === "production", // Hanya aktif di HTTPS pada produksi
      ttl: 7 * 24 * 60 * 60 * 1000, // 7 hari dalam milidetik
      path: "/",
      isHttpOnly: true,
    },
    validate: async (request, session) => {
      if (!session || !session.userId) {
        return { isValid: false }; // Sesi tidak valid jika tidak ada userId
      }

      // Sesi valid, kembalikan informasi pengguna (credentials)
      return {
        isValid: true,
        credentials: {
          userId: session.userId,
          username: session.username, // Opsional, data tambahan
        },
      };
    },
  });

  server.auth.default("session"); // Menjadikan strategi sesi sebagai default

  // Tambahkan routes
  server.route(authRoutes);

  // Jalankan server
  await server.start();
  console.log(`Server berjalan pada ${server.info.uri}`);
};

// Tangani unhandled rejection dan signal SIGINT untuk proses keluar
process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection:", err.message);
  process.exit(1);
});

process.on("SIGINT", () => {
  console.log("Server dihentikan.");
  process.exit(0);
});

// Inisialisasi server
init();
