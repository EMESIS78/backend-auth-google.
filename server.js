const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const cors = require("cors");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
console.log("CLIENT_ID:", CLIENT_ID);
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
console.log("CLIENT_SECRET:", CLIENT_SECRET ? "Cargado ✅" : "No cargado ❌");
const REDIRECT_URI = process.env.REDIRECT_URI;
console.log("REDIRECT_URI:", REDIRECT_URI);
const JWT_SECRET = process.env.JWT_SECRET || "secreto_super_seguro";

app.get("/auth/google/callback", async (req, res) => {
    const { code } = req.query;

    if (!code) {
        return res.status(400).json({ error: "Código de autorización no recibido" });
    }

    try {
        const { data } = await axios.post("https://oauth2.googleapis.com/token", null, {
            params: {
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uri: REDIRECT_URI,
                grant_type: "authorization_code",
                code,
            },
        });

        const userInfo = await axios.get("https://www.googleapis.com/oauth2/v2/userinfo", {
            headers: { Authorization: `Bearer ${data.access_token}` },
        });

        const jwtToken = jwt.sign(
            {
                id: userInfo.data.id,
                email: userInfo.data.email,
                name: userInfo.data.name,
            },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({ token: jwtToken, user: userInfo.data });
    } catch (error) {
        console.error("Error al autenticar:", error.response?.data || error.message);
        res.status(500).json({ error: "Error al intercambiar código por token" });
    }
});

// Middleware para verificar JWT
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Acceso denegado" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(403).json({ error: "Token inválido o expirado" });
    }
};

// Ruta para obtener datos del usuario autenticado
app.get("/api/user", verifyToken, (req, res) => {
    res.json({ user: req.user });
});

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`✅ Servidor corriendo en el puerto ${PORT}`));